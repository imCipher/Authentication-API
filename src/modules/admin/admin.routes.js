import { Router } from "express";

import validateRequest from "../../middlewares/validator.middleware.js";
import { getUsersSchema } from "./admin.validation.js";
import adminController from "./admin.controller.js";
import { protect } from "../../middlewares/auth.middleware.js";
import { authorize } from "../../middlewares/rbac.middleware.js";

const router = Router();

router.use(protect); // Apply authentication middleware to all routes in this router

// Admin-only routes
router.use(authorize("admin")); // Apply role-based access control middleware to all routes in this router

router.get("/users", validateRequest(getUsersSchema), adminController.getUsers);

export default router;
