import prisma from "../src/config/db.js";
import hashUtils from "../src/utils/hash.utils.js";

// Common lists to generate realistic-looking random names
const FIRST_NAMES = [
  "James",
  "Mary",
  "John",
  "Patricia",
  "Robert",
  "Jennifer",
  "Michael",
  "Linda",
  "William",
  "Elizabeth",
  "David",
  "Barbara",
  "Richard",
  "Susan",
  "Joseph",
  "Jessica",
  "Thomas",
  "Sarah",
  "Charles",
  "Karen",
  "Christopher",
  "Nancy",
  "Daniel",
  "Lisa",
  "Matthew",
  "Betty",
  "Anthony",
  "Margaret",
  "Mark",
  "Sandra",
];

const LAST_NAMES = [
  "Smith",
  "Johnson",
  "Williams",
  "Brown",
  "Jones",
  "Garcia",
  "Miller",
  "Davis",
  "Rodriguez",
  "Martinez",
  "Hernandez",
  "Lopez",
  "Gonzalez",
  "Wilson",
  "Anderson",
  "Thomas",
  "Taylor",
  "Moore",
  "Jackson",
  "Martin",
  "Lee",
  "Perez",
  "Thompson",
  "White",
];
const STATUSES = ["ACTIVE", "ACTIVE", "ACTIVE", "SUSPENDED", "DEACTIVATED"]; // mostly active

/**
 * Generates 50 random user objects
 */
const generateUsers = (passwordHash, count = 50) => {
  const users = [];

  for (let i = 1; i <= count; i++) {
    const firstName =
      FIRST_NAMES[Math.floor(Math.random() * FIRST_NAMES.length)];
    const lastName = LAST_NAMES[Math.floor(Math.random() * LAST_NAMES.length)];
    const randomStatus = STATUSES[Math.floor(Math.random() * STATUSES.length)];

    // Ensure username and email are unique by appending the index `i`
    const username = `${firstName.toLowerCase()}_${lastName.toLowerCase()}${i}`;
    const email = `${firstName.toLowerCase()}.${lastName.toLowerCase()}${i}@example.com`;

    users.push({
      fullName: `${firstName} ${lastName}`,
      username,
      email,
      passwordHash,
      role: "USER",
      status: randomStatus,
      emailVerified: Math.random() < 0.7, // 70% chance of being verified
    });
  }

  return users;
};

/**
 * Main seeding function
 */
async function main() {
  console.log("🌱 Starting user seed...");

  // Connect to database
  await prisma.$connect();

  // Hash a default password for all users
  console.log("🔒 Hashing default password...");
  const defaultPasswordHash = await hashUtils.hashPassword("SecureP@ss1");

  // Generate users
  const dummyUsers = generateUsers(defaultPasswordHash, 50);

  // Bulk insert using createMany (Fast single SQL query)
  console.log("💾 Inserting users into database...");
  const result = await prisma.user.createMany({
    data: dummyUsers,
    skipDuplicates: true, // Skip duplicates based on unique constraints
  });

  console.log(`✅ Successfully seeded ${result.count} users!`);
  console.log("🔑 All seeded users can log in with: SecureP@ss1");
}

main()
  .catch(error => {
    console.error("❌ Seeding failed:", error);
    process.exit(1);
  })
  .finally(async () => {
    // Always disconnect Prisma client when done
    await prisma.$disconnect();
    console.log("🔌 Disconnected from database.");
  });
