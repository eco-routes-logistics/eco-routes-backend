import { Router } from "express";
import { protect } from "../middleware/auth.middleware";
import { validateLogin } from "../middleware/validate.middleware";
import { login, getMe, logout } from "../controllers/auth.controller";
const router = Router();

// There is deliberately no public /register route: it let anyone create a staff
// account with any role (including super_admin). Staff accounts are created by
// admins via POST /team/users, and the first super admin via `npm run create-admin`.

// POST /api/v1/auth/login
router.post("/login", validateLogin, login);

// GET /api/v1/auth/me
router.get("/me", protect, getMe);

// POST /api/v1/auth/logout
router.post("/logout", protect, logout);

export default router;
