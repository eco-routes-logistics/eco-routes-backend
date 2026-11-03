/**
 * Creates the first super admin. Run on the server, never exposed over HTTP.
 *
 *   ADMIN_NAME="Ada Obi" ADMIN_EMAIL=ada@ecoroutes.com ADMIN_PHONE=08012345678 \
 *   ADMIN_PASSWORD='...' npm run create-admin
 *
 * Values come from environment variables (or .env) so the password never appears
 * in the command arguments. Refuses to overwrite an existing account.
 */
import dotenv from "dotenv";
import mongoose from "mongoose";
import User from "../models/user.model";
import { validatePasswordStrength } from "../middleware/validate.middleware";

dotenv.config();

const fail = (message: string): never => {
  console.error(`✖ ${message}`);
  process.exit(1);
};

const main = async (): Promise<void> => {
  const { MONGODB_URI, ADMIN_NAME, ADMIN_EMAIL, ADMIN_PHONE, ADMIN_PASSWORD } = process.env;

  if (!MONGODB_URI) fail("MONGODB_URI is not set.");
  if (!ADMIN_NAME || !ADMIN_EMAIL || !ADMIN_PHONE || !ADMIN_PASSWORD) {
    fail("Set ADMIN_NAME, ADMIN_EMAIL, ADMIN_PHONE and ADMIN_PASSWORD.");
  }

  const { isValid, errors } = validatePasswordStrength(ADMIN_PASSWORD!);
  if (!isValid) fail(`Password is too weak:\n  - ${errors.join("\n  - ")}`);

  await mongoose.connect(MONGODB_URI!);

  const email = ADMIN_EMAIL!.trim().toLowerCase();
  if (await User.exists({ email })) {
    await mongoose.disconnect();
    fail(`A user with ${email} already exists. Nothing was changed.`);
  }

  // Password is hashed by the User model's pre-save hook
  await User.create({
    name: ADMIN_NAME!.trim(),
    email,
    phone: ADMIN_PHONE!.trim(),
    password: ADMIN_PASSWORD,
    role: "super_admin",
    isActive: true,
  });

  console.log(`✔ Super admin created for ${email}. They can now sign in at /login.`);
  await mongoose.disconnect();
};

main().catch(async (error) => {
  console.error("✖ Failed to create super admin:", error);
  await mongoose.disconnect();
  process.exit(1);
});
