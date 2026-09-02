import { Router } from "express";

import validateRequest from "../../middlewares/validator.middleware.js";
import { protect } from "../../middlewares/auth.middleware.js";