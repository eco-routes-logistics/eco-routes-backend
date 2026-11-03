/**
 * Creates (or resets) one demo account per role so the app can be demoed at any time.
 *
 *   npm run seed:demo
 *
 * - Emails use the reserved .test domain, so future email flows can never reach a real inbox.
 * - The password comes from DEMO_PASSWORD (in .env). If unset, a strong one is generated and printed.
 * - Safe to re-run: existing demo accounts are reset to an active/approved state with the current password.
 * - Refuses to run when NODE_ENV=production unless ALLOW_DEMO_ACCOUNTS=true, because these
 *   accounts have a shared, known password.
 */
import crypto from "crypto";
import dotenv from "dotenv";
import mongoose from "mongoose";
import User from "../models/user.model";
import Client from "../models/client.model";
import Rider from "../models/rider.model";
import Wallet from "../models/wallet.model";
import WalletTransaction from "../models/wallet-transaction.model";
import { validatePasswordStrength } from "../middleware/validate.middleware";

dotenv.config();

const DEMO_WALLET_BALANCE = 50_000; // NGN, lets the demo business book deliveries without a payment gateway

const STAFF = [
  { email: "demo.superadmin@ecoroutes.test", name: "Demo Super Admin", role: "super_admin" },
  { email: "demo.admin@ecoroutes.test", name: "Demo Admin", role: "admin" },
  { email: "demo.staff@ecoroutes.test", name: "Demo Logistics Staff", role: "logistics_staff" },
] as const;

const CLIENTS = [
  { email: "demo.business@ecoroutes.test", company: "Demo Business (Pay as you go)", contactName: "Demo Business", accountType: "pay_as_you_go" },
  { email: "demo.corporate@ecoroutes.test", company: "Demo Corporate Ltd", contactName: "Demo Corporate", accountType: "corporate" },
] as const;

const RIDER = { email: "demo.rider@ecoroutes.test", firstName: "Demo", lastName: "Rider" };

const generatePassword = () => `Demo-${crypto.randomBytes(9).toString("base64url")}#7a`;

const fail = (message: string): never => {
  console.error(`✖ ${message}`);
  process.exit(1);
};

const main = async (): Promise<void> => {
  if (process.env.NODE_ENV === "production" && process.env.ALLOW_DEMO_ACCOUNTS !== "true") {
    fail("Refusing to create demo accounts with NODE_ENV=production. Set ALLOW_DEMO_ACCOUNTS=true if you really mean it.");
  }
  if (!process.env.MONGODB_URI) fail("MONGODB_URI is not set.");

  const generated = !process.env.DEMO_PASSWORD;
  const password = process.env.DEMO_PASSWORD || generatePassword();
  const { isValid, errors } = validatePasswordStrength(password);
  if (!isValid) fail(`DEMO_PASSWORD is too weak:\n  - ${errors.join("\n  - ")}`);

  await mongoose.connect(process.env.MONGODB_URI!);

  // Staff: save() so the model's pre-save hook hashes the password
  for (const s of STAFF) {
    const user = (await User.findOne({ email: s.email })) ?? new User({ email: s.email });
    Object.assign(user, { name: s.name, phone: "08000000000", role: s.role, isActive: true, password });
    await user.save();
  }

  // Business clients, approved, with a password (corporate sign-up has no password flow yet)
  for (const c of CLIENTS) {
    const client = (await Client.findOne({ email: c.email })) ?? new Client({ email: c.email });
    Object.assign(client, {
      company: c.company,
      contactName: c.contactName,
      phone: "08000000001",
      address: "1 Demo Street, Lagos",
      accountType: c.accountType,
      status: "active",
      password,
    });
    await client.save();

    if (c.accountType === "pay_as_you_go") {
      const wallet = (await Wallet.findOne({ clientId: client._id })) ?? (await Wallet.create({ clientId: client._id }));
      const topUp = DEMO_WALLET_BALANCE - wallet.balance;
      if (topUp > 0) {
        // Record the credit in the ledger so wallet history stays consistent
        await WalletTransaction.create({
          walletId: wallet._id,
          type: "credit",
          amount: topUp,
          balanceBefore: wallet.balance,
          balanceAfter: DEMO_WALLET_BALANCE,
          description: "Demo funds",
        });
        wallet.balance = DEMO_WALLET_BALANCE;
        await wallet.save();
      }
    }
  }

  // Rider, approved and online
  const rider = (await Rider.findOne({ email: RIDER.email })) ?? new Rider({ email: RIDER.email });
  Object.assign(rider, {
    firstName: RIDER.firstName,
    lastName: RIDER.lastName,
    phone: "08000000002",
    vehicleType: "Motorcycle",
    vehicleNumber: "DEMO 001 LG",
    riderType: "premium",
    status: "active",
    rejectionReason: undefined,
    password,
  });
  await rider.save();

  console.log("\n✔ Demo accounts ready\n");
  console.table([
    ...STAFF.map((s) => ({ role: s.role, email: s.email, signIn: "/login" })),
    ...CLIENTS.map((c) => ({ role: `client (${c.accountType})`, email: c.email, signIn: "/client/login" })),
    { role: "rider", email: RIDER.email, signIn: "/rider/login" },
  ]);
  console.log(
    generated
      ? `\nPassword for all demo accounts (generated, shown once):\n  ${password}\nAdd DEMO_PASSWORD=${password} to .env to keep it the same next time.\n`
      : "\nPassword for all demo accounts: the DEMO_PASSWORD value in your .env\n"
  );

  await mongoose.disconnect();
};

main().catch(async (error) => {
  console.error("✖ Failed to seed demo accounts:", error);
  await mongoose.disconnect();
  process.exit(1);
});
