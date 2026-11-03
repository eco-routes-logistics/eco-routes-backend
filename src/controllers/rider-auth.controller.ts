import { Request, Response } from "express";
import Rider from "../models/rider.model";
import { generateRiderToken } from "../utils/jwt.utils";
import { sendSuccess, sendError, HTTP } from "../utils/response.utils";
import { uploadFile } from "../services/upload.service";
import { notifyAdminNewRiderApplication } from "../services/email.service";
import { RiderJwtPayload } from "../types/rider.types";

// ---------------------------------------------------------------------------
// POST /api/v1/rider-auth/register
// Content-Type: multipart/form-data
// ---------------------------------------------------------------------------
export const registerRider = async (req: Request, res: Response): Promise<void> => {
  try {
    const {
      name,
      phone,
      email,
      password,
      vehicleType,
      vehicleNumber,
      nin,
      idType,
    } = req.body;

    // Split "name" into firstName / lastName (split on first space)
    const nameParts = String(name).trim().split(/\s+/);
    const firstName = nameParts[0];
    const lastName = nameParts.slice(1).join(" ") || nameParts[0]; // fallback to first name if single word

    // Duplicate email check
    const existing = await Rider.findOne({ email: String(email).toLowerCase() });
    if (existing) {
      sendError(res, "An account with this email already exists.", HTTP.CONFLICT);
      return;
    }

    // Files are attached by multer as req.files (typed below)
    const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;
    const idDocumentFile   = files?.["idDocument"]?.[0];
    const passportPhotoFile = files?.["passportPhoto"]?.[0];

    if (!idDocumentFile || !passportPhotoFile) {
      sendError(res, "Both idDocument and passportPhoto files are required.", HTTP.BAD_REQUEST);
      return;
    }

    // Upload both files in parallel
    const [idDocUpload, passportUpload] = await Promise.all([
      uploadFile(idDocumentFile.buffer, idDocumentFile.originalname, "kyc/id-documents"),
      uploadFile(passportPhotoFile.buffer, passportPhotoFile.originalname, "kyc/passport-photos"),
    ]);

    const rider = await Rider.create({
      firstName,
      lastName,
      phone,
      email,
      password,
      vehicleType,
      vehicleNumber,
      nin,
      idType,
      idDocumentUrl:    idDocUpload.url,
      passportPhotoUrl: passportUpload.url,
      riderType: "premium",
      status:    "pending",
    });

    // Fire-and-forget — email failure must never block the 201 response
    void notifyAdminNewRiderApplication({
      id:          rider.id as string,
      firstName:   rider.firstName,
      lastName:    rider.lastName,
      email:       rider.email,
      phone:       rider.phone,
      vehicleType: rider.vehicleType,
      createdAt:   rider.createdAt,
    });

    sendSuccess(
      res,
      {
        rider: {
          id:        rider.id,
          firstName: rider.firstName,
          lastName:  rider.lastName,
          email:     rider.email,
          status:    rider.status,
          riderType: rider.riderType,
        },
      },
      "Application submitted successfully. You will be notified once your account is approved.",
      HTTP.CREATED,
    );
  } catch (error) {
    console.error("Rider registration error:", error);
    sendError(res, "Error submitting application. Please try again.", HTTP.SERVER_ERROR);
  }
};

// ---------------------------------------------------------------------------
// POST /api/v1/rider-auth/login
// ---------------------------------------------------------------------------
export const riderLogin = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    const rider = await Rider.findOne({ email: String(email).toLowerCase() }).select("+password");
    if (!rider) {
      sendError(res, "Invalid email or password.", HTTP.UNAUTHORIZED);
      return;
    }

    const isValid = await rider.comparePassword(String(password));
    if (!isValid) {
      sendError(res, "Invalid email or password.", HTTP.UNAUTHORIZED);
      return;
    }

    // Status gate — three blocked states per spec
    if (rider.status === "pending") {
      sendError(
        res,
        "Your application is under review. You will be notified once approved.",
        HTTP.FORBIDDEN,
      );
      return;
    }

    if (rider.status === "rejected") {
      sendError(
        res,
        `Your application was not approved. Reason: ${rider.rejectionReason ?? "No reason provided."}`,
        HTTP.FORBIDDEN,
      );
      return;
    }

    if (rider.status === "inactive") {
      sendError(
        res,
        "Your account is inactive. Please contact the EcoRoutes team.",
        HTTP.FORBIDDEN,
      );
      return;
    }

    const payload: RiderJwtPayload = {
      id:        rider.id as string,
      email:     rider.email,
      riderType: rider.riderType,
      tokenType: "rider",
    };

    const token = generateRiderToken(payload);

    sendSuccess(res, {
      rider: {
        id:        rider.id,
        name:      `${rider.firstName} ${rider.lastName}`.trim(),
        firstName: rider.firstName,
        lastName:  rider.lastName,
        email:     rider.email,
        phone:     rider.phone,
        status:    rider.status,
        riderType: rider.riderType,
        vehicleType:   rider.vehicleType,
        vehicleNumber: rider.vehicleNumber,
        rating:        rider.rating,
      },
      token,
    });
  } catch (error) {
    console.error("Rider login error:", error);
    sendError(res, "An error occurred during login. Please try again.", HTTP.SERVER_ERROR);
  }
};
