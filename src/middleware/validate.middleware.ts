import { Request, Response, NextFunction } from "express";
import { sendError, HTTP } from "../utils/response.utils";
import { UserRole } from "../types/auth.types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type FieldError = { field: string; message: string };

const isValidEmail = (email: string): boolean =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const isValidPhone = (phone: string): boolean =>
  /^\+?[0-9]{7,15}$/.test(phone.replace(/\s/g, ""));

const VALID_ROLES: UserRole[] = ["super_admin", "admin", "logistics_staff", "rider"];

export const validatePasswordStrength = (
  password: string,
): { isValid: boolean; errors: string[] } => {
  const errors: string[] = [];
  if (password.length < 8) errors.push("Password must be at least 8 characters long");
  if (!/[A-Z]/.test(password)) errors.push("Password must contain at least one uppercase letter");
  if (!/[a-z]/.test(password)) errors.push("Password must contain at least one lowercase letter");
  if (!/[0-9]/.test(password)) errors.push("Password must contain at least one number");
  if (!/[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;'`~]/.test(password))
    errors.push("Password must contain at least one special character");
  return { isValid: errors.length === 0, errors };
};

const fail = (res: Response, errors: FieldError[]): void => {
  sendError(res, "Validation failed. Please correct the highlighted fields.", HTTP.BAD_REQUEST, errors);
};

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const validateRegister = (req: Request, res: Response, next: NextFunction): void => {
  const { name, email, phone, password, role } = req.body;
  const errors: FieldError[] = [];

  if (!name || typeof name !== "string" || name.trim().length < 2)
    errors.push({ field: "name", message: "Name must be at least 2 characters" });
  else if (name.trim().length > 100)
    errors.push({ field: "name", message: "Name cannot exceed 100 characters" });

  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });

  if (!phone || !isValidPhone(String(phone).trim()))
    errors.push({ field: "phone", message: "A valid phone number (7-15 digits) is required" });

  if (!password || typeof password !== "string" || password.length === 0) {
    errors.push({ field: "password", message: "Password is required" });
  } else {
    const { isValid, errors: pwErrors } = validatePasswordStrength(password);
    if (!isValid) pwErrors.forEach((msg) => errors.push({ field: "password", message: msg }));
  }

  if (!role || !VALID_ROLES.includes(role as UserRole))
    errors.push({ field: "role", message: `Role must be one of: ${VALID_ROLES.join(", ")}` });

  if (errors.length > 0) { fail(res, errors); return; }

  req.body.name = (name as string).trim();
  req.body.email = (email as string).trim().toLowerCase();
  req.body.phone = (phone as string).trim();
  next();
};

export const validateLogin = (req: Request, res: Response, next: NextFunction): void => {
  const { email, password } = req.body;
  const errors: FieldError[] = [];

  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });
  if (!password || typeof password !== "string" || password.length === 0)
    errors.push({ field: "password", message: "Password is required" });

  if (errors.length > 0) { fail(res, errors); return; }
  req.body.email = (email as string).trim().toLowerCase();
  next();
};

// ---------------------------------------------------------------------------
// Client Auth
// ---------------------------------------------------------------------------

export const validateClientRegisterPayAsYouGo = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const { company, contactName, email, phone, address, password } = req.body;
  const errors: FieldError[] = [];

  if (!company || typeof company !== "string" || company.trim().length < 2)
    errors.push({ field: "company", message: "Company name is required (min 2 characters)" });

  if (!contactName || typeof contactName !== "string" || contactName.trim().length < 2)
    errors.push({ field: "contactName", message: "Contact name is required (min 2 characters)" });

  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });

  if (!phone || !isValidPhone(String(phone).trim()))
    errors.push({ field: "phone", message: "A valid phone number is required" });

  if (!address || typeof address !== "string" || address.trim().length < 5)
    errors.push({ field: "address", message: "Address is required (min 5 characters)" });

  if (!password || typeof password !== "string" || password.length === 0) {
    errors.push({ field: "password", message: "Password is required" });
  } else {
    const { isValid, errors: pwErrors } = validatePasswordStrength(password);
    if (!isValid) pwErrors.forEach((msg) => errors.push({ field: "password", message: msg }));
  }

  if (errors.length > 0) { fail(res, errors); return; }
  req.body.email = (email as string).trim().toLowerCase();
  next();
};

export const validateClientRegisterCorporate = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const { company, contactName, email, phone, address, registrationNumber, estimatedMonthlyVolume } = req.body;
  const errors: FieldError[] = [];

  if (!company || typeof company !== "string" || company.trim().length < 2)
    errors.push({ field: "company", message: "Company name is required" });
  if (!contactName || typeof contactName !== "string" || contactName.trim().length < 2)
    errors.push({ field: "contactName", message: "Contact name is required" });
  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });
  if (!phone || !isValidPhone(String(phone).trim()))
    errors.push({ field: "phone", message: "A valid phone number is required" });
  if (!address || typeof address !== "string" || address.trim().length < 5)
    errors.push({ field: "address", message: "Address is required" });
  if (!registrationNumber || typeof registrationNumber !== "string" || registrationNumber.trim().length < 3)
    errors.push({ field: "registrationNumber", message: "Company registration number is required" });
  if (!estimatedMonthlyVolume || typeof estimatedMonthlyVolume !== "string")
    errors.push({ field: "estimatedMonthlyVolume", message: "Estimated monthly volume is required" });

  if (errors.length > 0) { fail(res, errors); return; }
  req.body.email = (email as string).trim().toLowerCase();
  next();
};

export const validateClientLogin = (req: Request, res: Response, next: NextFunction): void => {
  const { email, password } = req.body;
  const errors: FieldError[] = [];

  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });
  if (!password || typeof password !== "string" || password.length === 0)
    errors.push({ field: "password", message: "Password is required" });

  if (errors.length > 0) { fail(res, errors); return; }
  req.body.email = (email as string).trim().toLowerCase();
  next();
};

// ---------------------------------------------------------------------------
// Orders
// ---------------------------------------------------------------------------

const VALID_DELIVERY_TYPES = ["standard", "express", "same_day"];
const VALID_DELIVERY_MODELS = ["Standard", "Premium"];
const VALID_ORDER_STATUSES = ["pending", "assigned", "picked_up", "in_transit", "delivered", "cancelled"];

export const validateCreateOrder = (req: Request, res: Response, next: NextFunction): void => {
  const {
    pickupLocation, pickupContact, pickupPhone,
    customerName, customerPhone, customerAddress,
    description, weight, value, deliveryType, deliveryModel, businessClientId,
    scheduledFor,
  } = req.body;
  const errors: FieldError[] = [];

  if (!pickupLocation || typeof pickupLocation !== "string" || pickupLocation.trim().length < 3)
    errors.push({ field: "pickupLocation", message: "Pickup location is required" });
  if (!pickupContact || typeof pickupContact !== "string" || pickupContact.trim().length < 2)
    errors.push({ field: "pickupContact", message: "Pickup contact name is required" });
  if (!pickupPhone || !isValidPhone(String(pickupPhone).trim()))
    errors.push({ field: "pickupPhone", message: "A valid pickup phone number is required" });
  if (!customerName || typeof customerName !== "string" || customerName.trim().length < 2)
    errors.push({ field: "customerName", message: "Customer name is required" });
  if (!customerPhone || !isValidPhone(String(customerPhone).trim()))
    errors.push({ field: "customerPhone", message: "A valid customer phone number is required" });
  if (!customerAddress || typeof customerAddress !== "string" || customerAddress.trim().length < 5)
    errors.push({ field: "customerAddress", message: "Customer delivery address is required" });
  if (!description || typeof description !== "string" || description.trim().length < 3)
    errors.push({ field: "description", message: "Package description is required" });
  if (weight === undefined || weight === null || typeof weight !== "number" || weight <= 0)
    errors.push({ field: "weight", message: "Weight must be a positive number (kg)" });
  if (value === undefined || value === null || typeof value !== "number" || value < 0)
    errors.push({ field: "value", message: "Package value must be a non-negative number" });
  if (!deliveryType || !VALID_DELIVERY_TYPES.includes(deliveryType))
    errors.push({ field: "deliveryType", message: `Delivery type must be one of: ${VALID_DELIVERY_TYPES.join(", ")}` });
  if (!deliveryModel || !VALID_DELIVERY_MODELS.includes(deliveryModel))
    errors.push({ field: "deliveryModel", message: "Delivery model must be 'Standard' or 'Premium'" });
  if (!businessClientId || typeof businessClientId !== "string")
    errors.push({ field: "businessClientId", message: "Business client ID is required" });
  if (scheduledFor !== undefined && isNaN(Date.parse(scheduledFor))) {
    errors.push({ field: "scheduledFor", message: "scheduledFor must be a valid ISO 8601 datetime" });
  } else if (scheduledFor !== undefined && new Date(scheduledFor) <= new Date()) {
    errors.push({ field: "scheduledFor", message: "Scheduled delivery time must be in the future" });
  }

  if (errors.length > 0) { fail(res, errors); return; }
  next();
};

export const validateUpdateOrderStatus = (req: Request, res: Response, next: NextFunction): void => {
  const { status } = req.body;
  if (!status || !VALID_ORDER_STATUSES.includes(status)) {
    fail(res, [{ field: "status", message: `Status must be one of: ${VALID_ORDER_STATUSES.join(", ")}` }]);
    return;
  }
  next();
};

export const validateAssignRider = (req: Request, res: Response, next: NextFunction): void => {
  const { riderId } = req.body;
  if (!riderId || typeof riderId !== "string" || riderId.trim().length === 0) {
    fail(res, [{ field: "riderId", message: "Rider ID is required" }]);
    return;
  }
  next();
};

// ---------------------------------------------------------------------------
// Riders
// ---------------------------------------------------------------------------

export const validateCreateRider = (req: Request, res: Response, next: NextFunction): void => {
  const { firstName, lastName, phone, email, vehicleType, vehicleNumber, licenseNumber } = req.body;
  const errors: FieldError[] = [];

  if (!firstName || typeof firstName !== "string" || firstName.trim().length < 2)
    errors.push({ field: "firstName", message: "First name is required (min 2 characters)" });
  if (!lastName || typeof lastName !== "string" || lastName.trim().length < 2)
    errors.push({ field: "lastName", message: "Last name is required (min 2 characters)" });
  if (!phone || !isValidPhone(String(phone).trim()))
    errors.push({ field: "phone", message: "A valid phone number is required" });
  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });
  if (!vehicleType || typeof vehicleType !== "string" || vehicleType.trim().length < 2)
    errors.push({ field: "vehicleType", message: "Vehicle type is required" });
  if (!vehicleNumber || typeof vehicleNumber !== "string" || vehicleNumber.trim().length < 2)
    errors.push({ field: "vehicleNumber", message: "Vehicle number is required" });
  if (!licenseNumber || typeof licenseNumber !== "string" || licenseNumber.trim().length < 3)
    errors.push({ field: "licenseNumber", message: "License number is required" });

  if (errors.length > 0) { fail(res, errors); return; }
  req.body.email = (email as string).trim().toLowerCase();
  next();
};

// ---------------------------------------------------------------------------
// Clients (admin-created)
// ---------------------------------------------------------------------------

const VALID_ACCOUNT_TYPES = ["pay_as_you_go", "corporate"];

export const validateCreateClient = (req: Request, res: Response, next: NextFunction): void => {
  const { contactName, email, phone, company, accountType } = req.body;
  const errors: FieldError[] = [];

  if (!contactName || typeof contactName !== "string" || contactName.trim().length < 2)
    errors.push({ field: "contactName", message: "Contact name is required" });
  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });
  if (!phone || !isValidPhone(String(phone).trim()))
    errors.push({ field: "phone", message: "A valid phone number is required" });
  if (!company || typeof company !== "string" || company.trim().length < 2)
    errors.push({ field: "company", message: "Company name is required" });
  if (!accountType || !VALID_ACCOUNT_TYPES.includes(accountType))
    errors.push({ field: "accountType", message: "Account type must be 'pay_as_you_go' or 'corporate'" });

  if (errors.length > 0) { fail(res, errors); return; }
  req.body.email = (email as string).trim().toLowerCase();
  next();
};

// ---------------------------------------------------------------------------
// Team Users
// ---------------------------------------------------------------------------

const TEAM_ROLES: UserRole[] = ["admin", "logistics_staff", "rider"];

export const validateCreateTeamUser = (req: Request, res: Response, next: NextFunction): void => {
  const { name, email, phone, password, role } = req.body;
  const errors: FieldError[] = [];

  if (!name || typeof name !== "string" || name.trim().length < 2)
    errors.push({ field: "name", message: "Name is required (min 2 characters)" });
  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });
  if (!phone || !isValidPhone(String(phone).trim()))
    errors.push({ field: "phone", message: "A valid phone number is required" });
  if (!password || typeof password !== "string" || password.length === 0) {
    errors.push({ field: "password", message: "Password is required" });
  } else {
    const { isValid, errors: pwErrors } = validatePasswordStrength(password);
    if (!isValid) pwErrors.forEach((msg) => errors.push({ field: "password", message: msg }));
  }
  if (!role || !TEAM_ROLES.includes(role as UserRole))
    errors.push({ field: "role", message: `Role must be one of: ${TEAM_ROLES.join(", ")}` });

  if (errors.length > 0) { fail(res, errors); return; }
  req.body.email = (email as string).trim().toLowerCase();
  next();
};

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

export const validateFundAmount = (req: Request, res: Response, next: NextFunction): void => {
  const { amount } = req.body;

  if (amount === undefined || amount === null) {
    fail(res, [{ field: "amount", message: "Amount is required" }]);
    return;
  }
  if (typeof amount !== "number" || isNaN(amount) || !isFinite(amount)) {
    fail(res, [{ field: "amount", message: "Amount must be a valid number" }]);
    return;
  }
  if (amount <= 0) {
    fail(res, [{ field: "amount", message: "Amount must be greater than zero" }]);
    return;
  }
  if (amount > 10_000_000) {
    fail(res, [{ field: "amount", message: "Amount cannot exceed ₦10,000,000 per transaction" }]);
    return;
  }
  next();
};

// ---------------------------------------------------------------------------
// Rider KYC (multipart/form-data — text fields only; file presence is checked
// inside the controller after multer runs)
// ---------------------------------------------------------------------------

const VALID_ID_TYPES = ["voters_card", "drivers_license", "international_passport", "nin_card"];

export const validateRiderRegister = (req: Request, res: Response, next: NextFunction): void => {
  const { name, phone, email, password, vehicleType, vehicleNumber, nin, idType } = req.body;
  const errors: FieldError[] = [];

  if (!name || typeof name !== "string" || name.trim().length < 2)
    errors.push({ field: "name", message: "Full name is required (min 2 characters)" });

  if (!phone || !isValidPhone(String(phone).trim()))
    errors.push({ field: "phone", message: "A valid phone number is required" });

  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });

  if (!password || typeof password !== "string" || password.length === 0) {
    errors.push({ field: "password", message: "Password is required" });
  } else {
    const { isValid, errors: pwErrors } = validatePasswordStrength(password);
    if (!isValid) pwErrors.forEach((msg) => errors.push({ field: "password", message: msg }));
  }

  if (!vehicleType || typeof vehicleType !== "string" || vehicleType.trim().length < 2)
    errors.push({ field: "vehicleType", message: "Vehicle type is required" });

  if (!vehicleNumber || typeof vehicleNumber !== "string" || vehicleNumber.trim().length < 2)
    errors.push({ field: "vehicleNumber", message: "Vehicle plate / number is required" });

  // NIN: exactly 11 numeric digits
  if (!nin || typeof nin !== "string") {
    errors.push({ field: "nin", message: "NIN is required" });
  } else if (!/^\d{11}$/.test(nin.trim())) {
    errors.push({ field: "nin", message: "NIN must be exactly 11 numeric digits" });
  }

  if (!idType || !VALID_ID_TYPES.includes(String(idType))) {
    errors.push({
      field: "idType",
      message: `ID type must be one of: ${VALID_ID_TYPES.join(", ")}`,
    });
  }

  if (errors.length > 0) { fail(res, errors); return; }
  req.body.email = (email as string).trim().toLowerCase();
  req.body.nin   = (nin   as string).trim();
  next();
};

export const validateRiderLogin = (req: Request, res: Response, next: NextFunction): void => {
  const { email, password } = req.body;
  const errors: FieldError[] = [];

  if (!email || !isValidEmail(String(email).trim()))
    errors.push({ field: "email", message: "A valid email address is required" });
  if (!password || typeof password !== "string" || password.length === 0)
    errors.push({ field: "password", message: "Password is required" });

  if (errors.length > 0) { fail(res, errors); return; }
  req.body.email = (email as string).trim().toLowerCase();
  next();
};
