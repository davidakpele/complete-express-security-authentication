// src/utils/seed.js

const { pool } = require('../config/database');
const UserModel = require('../models/UserModel');
const dotenv = require('dotenv');

dotenv.config();

/**
 * Seed database with initial data
 */
const seedDatabase = async () => {
  try {
    console.log('🌱 Starting database seeding...');

    // Create admin user
    const adminExists = await UserModel.findByEmail('admin@example.com');
    
    if (!adminExists) {
      const admin = await UserModel.create({
        email: 'admin@example.com',
        password: 'Admin@123456',
        firstName: 'Admin',
        lastName: 'User',
        role: 'admin',
      });
      console.log('Admin user created:', admin.email);
    } else {
      console.log('Admin user already exists');
    }

    // Create moderator user
    const moderatorExists = await UserModel.findByEmail('moderator@example.com');
    
    if (!moderatorExists) {
      const moderator = await UserModel.create({
        email: 'moderator@example.com',
        password: 'Moderator@123456',
        firstName: 'Moderator',
        lastName: 'User',
        role: 'moderator',
      });
      console.log('Moderator user created:', moderator.email);
    } else {
      console.log('Moderator user already exists');
    }

    // Create regular user
    const userExists = await UserModel.findByEmail('user@example.com');
    
    if (!userExists) {
      const user = await UserModel.create({
        email: 'user@example.com',
        password: 'User@123456',
        firstName: 'Regular',
        lastName: 'User',
        role: 'user',
      });
      console.log('Regular user created:', user.email);
    } else {
      console.log('ℹRegular user already exists');
    }

    console.log('Database seeding completed!');
    console.log('\nDefault Users:');
    console.log('Admin: admin@example.com / Admin@123456');
    console.log('Moderator: moderator@example.com / Moderator@123456');
    console.log('User: user@example.com / User@123456');
    console.log('\ change these passwords in production!');

  } catch (error) {
    console.error('Seeding failed:', error);
    throw error;
  } finally {
    await pool.end();
  }
};

// Run seeder
seedDatabase()
  .then(() => {
    console.log('Seeder script completed');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Seeder script failed:', error);
    process.exit(1);
  });