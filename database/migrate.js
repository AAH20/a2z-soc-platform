const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

/**
 * Database Migration Runner for A2Z SOC
 * Manages database schema changes and tracks migration state
 */
class MigrationRunner {
  constructor() {
    this.pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });
    
    this.migrationsDir = path.join(__dirname, 'migrations');
    this.migrationTableName = 'schema_migrations';
  }

  /**
   * Initialize migration tracking table
   */
  async initializeMigrationTable() {
    const client = await this.pool.connect();
    
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${this.migrationTableName} (
          id SERIAL PRIMARY KEY,
          version VARCHAR(255) UNIQUE NOT NULL,
          name VARCHAR(255) NOT NULL,
          executed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          checksum VARCHAR(64) NOT NULL
        )
      `);
      
      console.log('✓ Migration tracking table initialized');
    } catch (error) {
      console.error('Failed to initialize migration table:', error.message);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Get list of available migration files
   */
  getAvailableMigrations() {
    if (!fs.existsSync(this.migrationsDir)) {
      console.log('No migrations directory found');
      return [];
    }

    const files = fs.readdirSync(this.migrationsDir)
      .filter(file => file.endsWith('.sql'))
      .sort();

    return files.map(file => {
      const version = file.replace('.sql', '');
      const filePath = path.join(this.migrationsDir, file);
      const content = fs.readFileSync(filePath, 'utf8');
      
      return {
        version,
        name: this.extractMigrationName(content),
        fileName: file,
        filePath,
        content,
        checksum: this.calculateChecksum(content)
      };
    });
  }

  /**
   * Extract migration name from SQL content
   */
  extractMigrationName(content) {
    const match = content.match(/-- Migration \d+: (.+)/);
    return match ? match[1].trim() : 'Unknown Migration';
  }

  /**
   * Calculate checksum for migration content
   */
  calculateChecksum(content) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Get list of executed migrations
   */
  async getExecutedMigrations() {
    const client = await this.pool.connect();
    
    try {
      const result = await client.query(
        `SELECT version, name, executed_at, checksum 
         FROM ${this.migrationTableName} 
         ORDER BY version ASC`
      );
      
      return result.rows;
    } catch (error) {
      if (error.code === '42P01') { // Table doesn't exist
        return [];
      }
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Get pending migrations
   */
  async getPendingMigrations() {
    const available = this.getAvailableMigrations();
    const executed = await this.getExecutedMigrations();
    const executedVersions = new Set(executed.map(m => m.version));

    return available.filter(migration => !executedVersions.has(migration.version));
  }

  /**
   * Validate migration checksums
   */
  async validateMigrations() {
    const available = this.getAvailableMigrations();
    const executed = await this.getExecutedMigrations();
    
    const issues = [];

    for (const executedMigration of executed) {
      const availableMigration = available.find(m => m.version === executedMigration.version);
      
      if (!availableMigration) {
        issues.push({
          type: 'missing_file',
          version: executedMigration.version,
          message: `Migration file for version ${executedMigration.version} not found`
        });
        continue;
      }

      if (availableMigration.checksum !== executedMigration.checksum) {
        issues.push({
          type: 'checksum_mismatch',
          version: executedMigration.version,
          message: `Migration ${executedMigration.version} has been modified after execution`
        });
      }
    }

    return issues;
  }

  /**
   * Execute a single migration
   */
  async executeMigration(migration) {
    const client = await this.pool.connect();
    
    try {
      await client.query('BEGIN');
      
      console.log(`\nExecuting migration: ${migration.version} - ${migration.name}`);
      console.log('-'.repeat(60));
      
      // Execute the migration SQL
      await client.query(migration.content);
      
      // Record the migration execution
      await client.query(
        `INSERT INTO ${this.migrationTableName} (version, name, checksum) 
         VALUES ($1, $2, $3)`,
        [migration.version, migration.name, migration.checksum]
      );
      
      await client.query('COMMIT');
      
      console.log(`✓ Migration ${migration.version} executed successfully`);
      
    } catch (error) {
      await client.query('ROLLBACK');
      console.error(`✗ Migration ${migration.version} failed:`, error.message);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Run all pending migrations
   */
  async migrate() {
    console.log('A2Z SOC Database Migration Runner');
    console.log('================================\n');

    try {
      // Initialize migration tracking
      await this.initializeMigrationTable();

      // Validate existing migrations
      const issues = await this.validateMigrations();
      if (issues.length > 0) {
        console.error('Migration validation failed:');
        issues.forEach(issue => {
          console.error(`  - ${issue.type}: ${issue.message}`);
        });
        throw new Error('Migration validation failed');
      }

      // Get pending migrations
      const pending = await this.getPendingMigrations();
      
      if (pending.length === 0) {
        console.log('✓ Database is up to date - no migrations to run');
        return;
      }

      console.log(`Found ${pending.length} pending migration(s):`);
      pending.forEach(migration => {
        console.log(`  - ${migration.version}: ${migration.name}`);
      });
      console.log('');

      // Execute pending migrations
      for (const migration of pending) {
        await this.executeMigration(migration);
      }

      console.log(`\n✓ Successfully executed ${pending.length} migration(s)`);
      
    } catch (error) {
      console.error('\n✗ Migration failed:', error.message);
      process.exit(1);
    }
  }

  /**
   * Show migration status
   */
  async status() {
    console.log('A2Z SOC Database Migration Status');
    console.log('=================================\n');

    try {
      await this.initializeMigrationTable();

      const available = this.getAvailableMigrations();
      const executed = await this.getExecutedMigrations();
      const pending = await this.getPendingMigrations();
      const issues = await this.validateMigrations();

      console.log(`Total migrations: ${available.length}`);
      console.log(`Executed: ${executed.length}`);
      console.log(`Pending: ${pending.length}`);
      console.log(`Issues: ${issues.length}\n`);

      if (issues.length > 0) {
        console.log('🚨 Issues found:');
        issues.forEach(issue => {
          console.log(`  - ${issue.type}: ${issue.message}`);
        });
        console.log('');
      }

      if (executed.length > 0) {
        console.log('📋 Executed migrations:');
        executed.forEach(migration => {
          console.log(`  ✓ ${migration.version} - ${migration.name} (${migration.executed_at})`);
        });
        console.log('');
      }

      if (pending.length > 0) {
        console.log('⏳ Pending migrations:');
        pending.forEach(migration => {
          console.log(`  - ${migration.version} - ${migration.name}`);
        });
        console.log('');
      }

      if (pending.length === 0 && issues.length === 0) {
        console.log('✅ Database is up to date and healthy');
      }

    } catch (error) {
      console.error('Failed to get migration status:', error.message);
      process.exit(1);
    }
  }

  /**
   * Create a new migration file
   */
  async createMigration(name) {
    if (!name) {
      console.error('Migration name is required');
      console.log('Usage: npm run migrate:create <migration_name>');
      process.exit(1);
    }

    // Get next migration number
    const existing = this.getAvailableMigrations();
    const nextNumber = existing.length > 0 
      ? Math.max(...existing.map(m => parseInt(m.version.split('_')[0]))) + 1
      : 1;

    const paddedNumber = nextNumber.toString().padStart(3, '0');
    const sanitizedName = name.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
    const fileName = `${paddedNumber}_${sanitizedName}.sql`;
    const filePath = path.join(this.migrationsDir, fileName);

    // Create migrations directory if it doesn't exist
    if (!fs.existsSync(this.migrationsDir)) {
      fs.mkdirSync(this.migrationsDir, { recursive: true });
    }

    // Create migration file template
    const template = `-- Migration ${paddedNumber}: ${name}
-- Created: ${new Date().toISOString().split('T')[0]}

-- Add your migration SQL here

-- Example:
-- CREATE TABLE example_table (
--     id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
--     name VARCHAR(255) NOT NULL,
--     created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
-- );

-- CREATE INDEX idx_example_table_name ON example_table(name);
`;

    fs.writeFileSync(filePath, template);
    
    console.log(`✓ Created migration: ${fileName}`);
    console.log(`  Location: ${filePath}`);
    console.log('\nEdit the file to add your migration SQL, then run:');
    console.log('  npm run migrate');
  }

  /**
   * Rollback last migration (development only)
   */
  async rollback() {
    if (process.env.NODE_ENV === 'production') {
      console.error('Rollback is not allowed in production');
      process.exit(1);
    }

    console.log('⚠️  Rolling back last migration (development only)');
    
    const executed = await this.getExecutedMigrations();
    if (executed.length === 0) {
      console.log('No migrations to rollback');
      return;
    }

    const lastMigration = executed[executed.length - 1];
    
    console.log(`Rolling back: ${lastMigration.version} - ${lastMigration.name}`);
    
    // This is a simple implementation - in a real system you might want
    // to have explicit rollback SQL for each migration
    const client = await this.pool.connect();
    
    try {
      await client.query('BEGIN');
      
      await client.query(
        `DELETE FROM ${this.migrationTableName} WHERE version = $1`,
        [lastMigration.version]
      );
      
      await client.query('COMMIT');
      
      console.log('✓ Rollback completed');
      console.log('⚠️  Note: Only the migration record was removed.');
      console.log('   You may need to manually undo schema changes.');
      
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Rollback failed:', error.message);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Close database connection
   */
  async close() {
    await this.pool.end();
  }
}

// CLI interface
async function main() {
  const command = process.argv[2];
  const migrationName = process.argv[3];
  
  const runner = new MigrationRunner();
  
  try {
    switch (command) {
      case 'migrate':
      case 'up':
        await runner.migrate();
        break;
        
      case 'status':
        await runner.status();
        break;
        
      case 'create':
        await runner.createMigration(migrationName);
        break;
        
      case 'rollback':
      case 'down':
        await runner.rollback();
        break;
        
      default:
        console.log('A2Z SOC Database Migration Runner\n');
        console.log('Usage:');
        console.log('  node migrate.js migrate     - Run pending migrations');
        console.log('  node migrate.js status      - Show migration status');
        console.log('  node migrate.js create <name> - Create new migration');
        console.log('  node migrate.js rollback    - Rollback last migration (dev only)');
        break;
    }
  } finally {
    await runner.close();
  }
}

// Run CLI if called directly
if (require.main === module) {
  main().catch(error => {
    console.error('Migration runner error:', error);
    process.exit(1);
  });
}

module.exports = MigrationRunner; 