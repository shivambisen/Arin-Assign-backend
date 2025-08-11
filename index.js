const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
let pool;
try {
  // For now, use in-memory storage to avoid SSL issues
  // You can uncomment the PostgreSQL connection when SSL is configured properly
  /*
  if (process.env.DATABASE_URL && process.env.DATABASE_URL !== 'postgresql://username:password@localhost:5432/campaign_tracker') {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: true
    });
  } else {
    throw new Error('No valid database URL provided');
  }
  */
  throw new Error('Using in-memory storage for development');
} catch (error) {
  console.warn('Database connection failed, using in-memory storage for development');
  // For development, we'll use a simple in-memory storage
  const inMemoryDB = {
    users: [],
    metrics: [],
    nextUserId: 1,
    nextMetricId: 1
  };
  
  pool = {
    query: async (text, params) => {
      // Simple in-memory database implementation
      if (text.includes('CREATE TABLE')) {
        return { rows: [] };
      }
      
      if (text.includes('INSERT INTO users')) {
        const user = {
          id: inMemoryDB.nextUserId++,
          email: params[0],
          password: params[1],
          created_at: new Date().toISOString()
        };
        inMemoryDB.users.push(user);
        return { rows: [{ id: user.id, email: user.email }] };
      }
      
      if (text.includes('SELECT * FROM users WHERE email')) {
        const user = inMemoryDB.users.find(u => u.email === params[0]);
        return { rows: user ? [{ id: user.id, email: user.email, password: user.password }] : [] };
      }
      
      if (text.includes('INSERT INTO metrics')) {
        const metric = {
          id: inMemoryDB.nextMetricId++,
          user_id: params[0],
          campaign_name: params[1],
          date: params[2],
          impressions: params[3],
          clicks: params[4],
          conversions: params[5],
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        inMemoryDB.metrics.push(metric);
        return { rows: [metric] };
      }
      
      if (text.includes('SELECT * FROM metrics WHERE user_id')) {
        let metrics = inMemoryDB.metrics.filter(m => m.user_id === params[0]);
        if (params[1] && text.includes('campaign_name ILIKE')) {
          const searchTerm = params[1].replace(/%/g, '');
          metrics = metrics.filter(m => 
            m.campaign_name.toLowerCase().includes(searchTerm.toLowerCase())
          );
        }
        return { rows: metrics.sort((a, b) => new Date(b.date) - new Date(a.date)) };
      }
      
      if (text.includes('UPDATE metrics')) {
        const metricId = parseInt(params[5]);
        const userId = params[6];
        const metricIndex = inMemoryDB.metrics.findIndex(m => m.id === metricId && m.user_id === userId);
        if (metricIndex !== -1) {
          inMemoryDB.metrics[metricIndex] = {
            ...inMemoryDB.metrics[metricIndex],
            campaign_name: params[0],
            date: params[1],
            impressions: params[2],
            clicks: params[3],
            conversions: params[4],
            updated_at: new Date().toISOString()
          };
          return { rows: [inMemoryDB.metrics[metricIndex]] };
        }
        return { rows: [] };
      }
      
      if (text.includes('DELETE FROM metrics')) {
        const metricId = parseInt(params[0]);
        const userId = params[1];
        const metricIndex = inMemoryDB.metrics.findIndex(m => m.id === metricId && m.user_id === userId);
        if (metricIndex !== -1) {
          const deletedMetric = inMemoryDB.metrics.splice(metricIndex, 1)[0];
          return { rows: [deletedMetric] };
        }
        return { rows: [] };
      }
      
      return { rows: [] };
    }
  };
}

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Initialize database tables
const initDatabase = async () => {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create metrics table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS metrics (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        campaign_name VARCHAR(255) NOT NULL,
        date DATE NOT NULL,
        impressions INTEGER NOT NULL,
        clicks INTEGER NOT NULL,
        conversions INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database tables initialized');
  } catch (error) {
    console.error('Database initialization error:', error);
    // Continue with in-memory storage even if initialization fails
  }
};

// Auth Routes
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Check if user already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword]
    );

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser.rows[0].id, email: newUser.rows[0].email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: newUser.rows[0].id, email: newUser.rows[0].email }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.rows[0].id, email: user.rows[0].email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.rows[0].id, email: user.rows[0].email }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Metrics Routes
app.post('/metrics', authenticateToken, async (req, res) => {
  try {
    const { campaign_name, date, impressions, clicks, conversions } = req.body;
    const userId = req.user.userId;

    if (!campaign_name || !date || impressions === undefined || clicks === undefined || conversions === undefined) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const newMetric = await pool.query(
      'INSERT INTO metrics (user_id, campaign_name, date, impressions, clicks, conversions) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [userId, campaign_name, date, impressions, clicks, conversions]
    );

    res.status(201).json(newMetric.rows[0]);
  } catch (error) {
    console.error('Create metric error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/metrics', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { campaign_name } = req.query;

    let query = 'SELECT * FROM metrics WHERE user_id = $1';
    let params = [userId];

    if (campaign_name) {
      query += ' AND campaign_name ILIKE $2';
      params.push(`%${campaign_name}%`);
    }

    query += ' ORDER BY date DESC';

    const metrics = await pool.query(query, params);
    res.json(metrics.rows);
  } catch (error) {
    console.error('Get metrics error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/metrics/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { campaign_name, date, impressions, clicks, conversions } = req.body;
    const userId = req.user.userId;

    if (!campaign_name || !date || impressions === undefined || clicks === undefined || conversions === undefined) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const updatedMetric = await pool.query(
      'UPDATE metrics SET campaign_name = $1, date = $2, impressions = $3, clicks = $4, conversions = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6 AND user_id = $7 RETURNING *',
      [campaign_name, date, impressions, clicks, conversions, id, userId]
    );

    if (updatedMetric.rows.length === 0) {
      return res.status(404).json({ error: 'Metric not found' });
    }

    res.json(updatedMetric.rows[0]);
  } catch (error) {
    console.error('Update metric error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/metrics/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;

    const deletedMetric = await pool.query(
      'DELETE FROM metrics WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, userId]
    );

    if (deletedMetric.rows.length === 0) {
      return res.status(404).json({ error: 'Metric not found' });
    }

    res.json({ message: 'Metric deleted successfully' });
  } catch (error) {
    console.error('Delete metric error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

// Initialize database and start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}); 