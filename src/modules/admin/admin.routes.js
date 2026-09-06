import { Router } from "express";

import validateRequest from "../../middlewares/validator.middleware.js";
import adminSchema from "./admin.validation.js";
import adminController from "./admin.controller.js";
import {
  adminReadRateLimiter,
  adminSensitiveMutationRateLimiter,
  adminHeavyMaintenanceRateLimiter,
} from "../../middlewares/rateLimiter.middleware.js";
import { protect } from "../../middlewares/auth.middleware.js";
import { authorize } from "../../middlewares/rbac.middleware.js";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Admin
 *   description: Admin-only endpoints for managing users and system settings.
 */

router.use(protect); // Apply authentication middleware to all routes in this router

// Admin-only routes
router.use(authorize("admin")); // Apply role-based access control middleware to all routes in this router

/**
 * @swagger
 * /admin/users:
 *   get:
 *    summary: Fetch a paginated list of users with optional filters (Admin-only)
 *    description: Retrieve a paginated list of users with optional filtering, searching, and sorting. This endpoint is restricted to admin users only.
 *    tags: [Admin]
 *    parameters:
 *      - in: query
 *        name: page
 *        schema:
 *          type: integer
 *          default: 1
 *          minimum: 1
 *        description: "Page number for pagination"
 *      - in: query
 *        name: limit
 *        schema:
 *           type: integer
 *           default: 10
 *           minimum: 1
 *           maximum: 100
 *        description: "Number of records to return per page (maximum 100)"
 *      - in: query
 *        name: role
 *        schema:
 *           type: string
 *           enum: [USER, ADMIN]
 *        description: "Filter users by account role (USER or ADMIN)"
 *      - in: query
 *        name: status
 *        schema:
 *           type: string
 *           enum: [ACTIVE, SUSPENDED, DEACTIVATED]
 *        description: "Filter users by account status (ACTIVE, SUSPENDED, DEACTIVATED)"
 *      - in: query
 *        name: search
 *        schema:
 *           type: string
 *        description: "Search term to match against email, username, or full name (max 100 characters)"
 *      - in: query
 *        name: sortBy
 *        schema:
 *           type: string
 *           enum: [createdAt, fullName, email, username, lastLoginAt]
 *           default: createdAt
 *        description: "Field to sort the results by (default: createdAt)"
 *      - in: query
 *        name: sortOrder
 *        schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *        description: "Order to sort the results by (default: desc)"
 *    responses:
 *      200:
 *        description: Users retrieved successfully with pagination metadata.
 *        content:
 *          application/json:
 *            schema:
 *              allOf:
 *                  - $ref: '#/components/schemas/ApiSuccess'
 *                  - type: object
 *                    properties:
 *                          data:
 *                              type: object
 *                              properties:
 *                                  users:
 *                                     type: array
 *                                     items:
 *                                       $ref: '#/components/schemas/User'
 *                                  pagination:
 *                                     type: object
 *                                     properties:
 *                                        totalCount:
 *                                          type: integer
 *                                          example: 150
 *                                          description: Total number of users matching the query
 *                                        totalPages:
 *                                          type: integer
 *                                          example: 15
 *                                          description: Total number of pages of users matching the query
 *                                        currentPage:
 *                                          type: integer
 *                                          example: 1
 *                                          description: Current page of users matching the query
 *                                        limit:
 *                                          type: integer
 *                                          example: 10
 *                                          description: Number of users per page
 *                                        hasNextPage:
 *                                          type: boolean
 *                                          example: true
 *                                          description: Indicates if there is a next page of users
 *                                        hasPrevPage:
 *                                          type: boolean
 *                                          example: false
 *                                          description: Indicates if there is a previous page of users
 *      400:
 *        description: Validation failed. Invalid query parameters provided.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiValidationError'
 *      401:
 *        description: Unauthorized. Please provide valid authentication credentials.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 *      403:
 *        description: Forbidden. You do not have permission to access this resource.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 *      429:
 *        description: Too many requests. Rate limit exceeded.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.get(
  "/users",
  adminReadRateLimiter,
  validateRequest(adminSchema.getUsersSchema),
  adminController.getUsers,
);

/**
 * @swagger
 * /admin/users/{id}:
 *   get:
 *    summary: Fetch a specific user by ID (Admin-only)
 *    description: Retrieve a specific user by their unique ID. This endpoint is restricted to admin users only.
 *    parameters:
 *      - in: path
 *        name: id
 *        schema:
 *          type: string
 *          format: uuid
 *        required: true
 *        description: The unique identifier of the user (UUID)
 *    tags: [Admin]
 *    responses:
 *      200:
 *        description: User retrieved successfully.
 *        content:
 *          application/json:
 *            schema:
 *              allOf:
 *                  - $ref: '#/components/schemas/ApiSuccess'
 *                  - type: object
 *                    properties:
 *                       user:
 *                         $ref: '#/components/schemas/User'
 *      400:
 *        description: Validation failed. Invalid query parameters provided.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiValidationError'
 *      401:
 *        description: Unauthorized. Please provide valid authentication credentials.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 *      403:
 *        description: Forbidden. You do not have permission to access this resource.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 *      429:
 *        description: Too many requests. Rate limit exceeded.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.get(
  "/users/:id",
  adminReadRateLimiter,
  validateRequest(adminSchema.userIdParamsSchema),
  adminController.getUserById,
);

/**
 * @swagger
 * /admin/users/{id}:
 *   patch:
 *     summary: Update a user's role and/or status (Admin-only)
 *     description: Partially update a specific user's account role or status by their unique ID. At least one field (role or status) must be provided in the request body. Restricted to admin users only.
 *     tags: [Admin]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *           format: uuid
 *         required: true
 *         description: The unique identifier of the user (UUID)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *                 enum: [USER, ADMIN]
 *                 description: "New account role to assign to the user"
 *                 example: "ADMIN"
 *               status:
 *                 type: string
 *                 enum: [ACTIVE, SUSPENDED, DEACTIVATED]
 *                 description: "New account status to set for the user"
 *                 example: "SUSPENDED"
 *     responses:
 *       200:
 *         description: User updated successfully.
 *         content:
 *           application/json:
 *            schema:
 *              allOf:
 *                - $ref: '#/components/schemas/ApiSuccess'
 *                - type: object
 *                  properties:
 *                    data:
 *                      type: object
 *                      properties:
 *                        user:
 *                          $ref: '#/components/schemas/User'
 *       400:
 *         description: Validation failed, empty update body, or invalid user ID format.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiValidationError'
 *       401:
 *         description: Unauthorized. Please provide valid authentication credentials.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *       403:
 *         description: Forbidden. Insufficient permissions, self-demotion, or attempting to modify the last active admin.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *       404:
 *         description: User not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *       429:
 *         description: Too many requests. Rate limit exceeded.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 */
router.patch(
  "/users/:id",
  adminSensitiveMutationRateLimiter,
  validateRequest(adminSchema.patchUserSchema),
  adminController.updateUser,
);

/**
 * @swagger
 * /admin/users/{id}/unlock:
 *   post:
 *    summary: Unlock a user's account (Admin-only)
 *    description: Unlock a specific user's account that was locked due to multiple failed login attempts. This endpoint is restricted to admin users only.
 *    tags: [Admin]
 *    parameters:
 *      - in: path
 *        name: id
 *        schema:
 *          type: string
 *          format: uuid
 *        required: true
 *        description: The unique identifier of the user (UUID)
 *    responses:
 *      200:
 *         description: User updated successfully.
 *         content:
 *           application/json:
 *            schema:
 *              allOf:
 *                - $ref: '#/components/schemas/ApiSuccess'
 *                - type: object
 *                  properties:
 *                    data:
 *                      type: object
 *                      properties:
 *                        user:
 *                          $ref: '#/components/schemas/User'
 *      400:
 *         description: Validation failed, empty update body, or invalid user ID format.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiValidationError'
 *      401:
 *         description: Unauthorized. Please provide valid authentication credentials.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *      403:
 *         description: Forbidden. Insufficient permissions, self-demotion, or attempting to modify the last active admin.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *      404:
 *         description: User not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *      429:
 *         description: Too many requests. Rate limit exceeded.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 */
router.post(
  "/users/:id/unlock",
  adminSensitiveMutationRateLimiter,
  validateRequest(adminSchema.userIdParamsSchema),
  adminController.unlockUserAccount,
);

/**
 * @swagger
 * /admin/users/{id}/logout-all:
 *   post:
 *    summary: Log out a user from all devices (Admin-only)
 *    description: Log out a specific user from all devices by invalidating their active sessions. This endpoint is restricted to admin users only.
 *    tags: [Admin]
 *    parameters:
 *      - in: path
 *        name: id
 *        schema:
 *          type: string
 *          format: uuid
 *        required: true
 *        description: The unique identifier of the user (UUID)
 *    responses:
 *      200:
 *        description: User logged out from all devices successfully.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiSuccess'
 *      400:
 *         description: Validation failed, empty update body, or invalid user ID format.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiValidationError'
 *      401:
 *         description: Unauthorized. Please provide valid authentication credentials.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *      403:
 *         description: Forbidden. Insufficient permissions, self-demotion, or attempting to modify the last active admin.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *      404:
 *         description: User not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *      429:
 *         description: Too many requests. Rate limit exceeded.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 */
router.post(
  "/users/:id/logout-all",
  adminSensitiveMutationRateLimiter,
  validateRequest(adminSchema.userIdParamsSchema),
  adminController.logoutUserFromAllDevices,
);

/**
 * @swagger
 * /admin/users/{id}:
 *   delete:
 *    summary: Delete a user account (Admin-only)
 *    description: Permanently delete a specific user's account by their unique ID. This action is irreversible and restricted to admin users only.
 *    tags: [Admin]
 *    parameters:
 *      - in: path
 *        name: id
 *        schema:
 *          type: string
 *          format: uuid
 *        required: true
 *        description: The unique identifier of the user (UUID)
 *    responses:
 *      200:
 *        description: User deleted successfully.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiSuccess'
 *      400:
 *         description: Validation failed, empty update body, or invalid user ID format.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiValidationError'
 *      401:
 *         description: Unauthorized. Please provide valid authentication credentials.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *      403:
 *         description: Forbidden. Insufficient permissions, self-demotion, or attempting to modify the last active admin.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *      404:
 *         description: User not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *      429:
 *         description: Too many requests. Rate limit exceeded.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 */
router.delete(
  "/users/:id",
  adminSensitiveMutationRateLimiter,
  validateRequest(adminSchema.userIdParamsSchema),
  adminController.deleteUser,
);

/**
 * @swagger
 * /admin/audit-logs:
 *   get:
 *     summary: Fetch a paginated list of audit logs with optional filters (Admin-only)
 *     description: Retrieve a paginated list of system audit logs with optional searching and sorting. Restricted to admin users only.
 *     tags: [Admin]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *           minimum: 1
 *         description: Page number for pagination
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *           minimum: 1
 *           maximum: 100
 *         description: Number of records to return per page (maximum 100)
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *           maxLength: 100
 *         description: Search term matching actor (email, username, full name), IP address, resource, or details context
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [createdAt, action, adminId, targetUserId]
 *           default: createdAt
 *         description: Field to sort the results by (default: createdAt)
 *       - in: query
 *         name: sortOrder
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *         description: Order to sort the results by (default: desc)
 *     responses:
 *       200:
 *         description: Audit logs retrieved successfully with pagination metadata.
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiSuccess'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         auditLogs:
 *                           type: array
 *                           items:
 *                             type: object
 *                             properties:
 *                               id:
 *                                 type: string
 *                                 format: uuid
 *                                 example: "716676c0-0fc4-4d58-ae24-baf33d865e12"
 *                               userId:
 *                                 type: string
 *                                 format: uuid
 *                                 nullable: true
 *                                 example: "4b92b0c3-f09c-4874-8aa7-71bbf5ef5cf6"
 *                               action:
 *                                 type: string
 *                                 enum:
 *                                   - PASSWORD_CHANGE
 *                                   - PASSWORD_RESET
 *                                   - EMAIL_CHANGE
 *                                   - EMAIL_VERIFIED
 *                                   - ROLE_CHANGE
 *                                   - STATUS_CHANGE
 *                                   - ACCOUNT_UNLOCKED
 *                                   - OAUTH_ACCOUNT_LINKED
 *                                   - TOKEN_REUSE_DETECTED
 *                                   - LOGOUT_ALL
 *                                   - ACCOUNT_DELETED
 *                                   - ACCOUNT_LOCKED
 *                                 example: "ROLE_CHANGE"
 *                               resource:
 *                                 type: string
 *                                 nullable: true
 *                                 example: "USER"
 *                               details:
 *                                 type: object
 *                                 nullable: true
 *                                 example:
 *                                   targetUserId: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
 *                                   previousRole: "USER"
 *                                   newRole: "ADMIN"
 *                               ipAddress:
 *                                 type: string
 *                                 nullable: true
 *                                 example: "192.168.1.1"
 *                               userAgent:
 *                                 type: string
 *                                 nullable: true
 *                                 example: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
 *                               success:
 *                                 type: boolean
 *                                 example: true
 *                               createdAt:
 *                                 type: string
 *                                 format: date-time
 *                                 example: "2026-09-06T12:00:00.000Z"
 *                               user:
 *                                 type: object
 *                                 nullable: true
 *                                 properties:
 *                                   id:
 *                                     type: string
 *                                     format: uuid
 *                                     example: "4b92b0c3-f09c-4874-8aa7-71bbf5ef5cf6"
 *                                   fullName:
 *                                     type: string
 *                                     example: "Admin User"
 *                                   username:
 *                                     type: string
 *                                     example: "admin_user"
 *                                   email:
 *                                     type: string
 *                                     format: email
 *                                     example: "admin@example.com"
 *                                   role:
 *                                     type: string
 *                                     example: "ADMIN"
 *                         pagination:
 *                           type: object
 *                           properties:
 *                             totalCount:
 *                               type: integer
 *                               example: 150
 *                               description: Total number of audit logs matching the query
 *                             totalPages:
 *                               type: integer
 *                               example: 15
 *                               description: Total number of pages
 *                             currentPage:
 *                               type: integer
 *                               example: 1
 *                               description: Current page number
 *                             limit:
 *                               type: integer
 *                               example: 10
 *                               description: Number of records per page
 *                             hasNextPage:
 *                               type: boolean
 *                               example: true
 *                               description: Indicates if there is a next page
 *                             hasPrevPage:
 *                               type: boolean
 *                               example: false
 *                               description: Indicates if there is a previous page
 *       400:
 *         description: Validation failed. Invalid query parameters provided.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiValidationError'
 *       401:
 *         description: Unauthorized. Please provide valid authentication credentials.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *       403:
 *         description: Forbidden. Insufficient permissions, admin access required.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *       429:
 *         description: Too many requests. Rate limit exceeded.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 */
router.get(
  "/audit-logs",
  adminReadRateLimiter,
  validateRequest(adminSchema.getAuditLogsSchema),
  adminController.getAuditLogs,
);

export default router;
