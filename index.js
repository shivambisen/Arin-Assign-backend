const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Ensure uploads directory exists and is served statically
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
	fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// Multer configuration for images/videos (use memory storage to also store in DB)
const storage = multer.memoryStorage();
const fileFilter = (req, file, cb) => {
	if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
		cb(null, true);
	} else {
		cb(new Error('Only images and videos are allowed'));
	}
};
const upload = multer({ storage, fileFilter, limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB

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
		media: [],
		nextUserId: 1,
		nextMetricId: 1,
		nextMediaId: 1
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
			
			if (text.includes('SELECT * FROM metrics WHERE user_id') && !text.includes('ORDER BY')) {
				let metrics = inMemoryDB.metrics.filter(m => m.user_id === params[0]);
				if (params[1] && text.includes('campaign_name ILIKE')) {
					const searchTerm = params[1].replace(/%/g, '');
					metrics = metrics.filter(m => 
						m.campaign_name.toLowerCase().includes(searchTerm.toLowerCase())
					);
				}
				return { rows: metrics };
			}
			
			if (text.includes('SELECT * FROM metrics WHERE user_id') && text.includes('ORDER BY')) {
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
					// Also cascade delete media for this metric
					inMemoryDB.media = inMemoryDB.media.filter(m => m.metric_id !== deletedMetric.id || m.user_id !== userId);
					return { rows: [deletedMetric] };
				}
				return { rows: [] };
			}
			
			// MEDIA: insert (with binary data)
			if (text.includes('INSERT INTO media')) {
				const media = {
					id: inMemoryDB.nextMediaId++,
					user_id: params[0],
					metric_id: params[1],
					filename: params[2],
					originalname: params[3],
					mimetype: params[4],
					size: params[5],
					url: params[6],
					data: params[7],
					created_at: new Date().toISOString()
				};
				inMemoryDB.media.push(media);
				return { rows: [media] };
			}
			
			// MEDIA: select by metric and user (any column list)
			if (text.includes('FROM media WHERE metric_id') && text.includes('user_id')) {
				const metricId = params[0];
				const userId = params[1];
				let media = inMemoryDB.media.filter(m => m.metric_id === metricId && m.user_id === userId);
				// Order by created_at DESC
				media = media.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
				return { rows: media };
			}
			
			// MEDIA: select by id and user
			if (text.includes('FROM media WHERE id') && text.includes('user_id')) {
				const id = params[0];
				const userId = params[1];
				const media = inMemoryDB.media.find(m => m.id === id && m.user_id === userId);
				return { rows: media ? [media] : [] };
			}
			
			return { rows: [] };
		}
	};
}

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
// Allow disabling auth only when explicitly set
const DISABLE_AUTH = process.env.DISABLE_AUTH === 'true';

// Authentication middleware
const authenticateToken = (req, res, next) => {
	// Short-circuit auth only when explicitly disabled
	if (DISABLE_AUTH) {
		if (!req.user) {
			req.user = { userId: 1, email: 'dev@local' };
		}
		return next();
	}
	const authHeader = req.headers['authorization'];
	const headerToken = authHeader && authHeader.split(' ')[1];
	const queryToken = req.query && req.query.token;
	const token = headerToken || queryToken;

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

		// Create media table (includes binary data)
		await pool.query(`
			CREATE TABLE IF NOT EXISTS media (
				id SERIAL PRIMARY KEY,
				user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
				metric_id INTEGER REFERENCES metrics(id) ON DELETE CASCADE,
				filename VARCHAR(512) NOT NULL,
				originalname VARCHAR(512),
				mimetype VARCHAR(128) NOT NULL,
				size BIGINT,
				url TEXT NOT NULL,
				data BYTEA,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

// Media upload & listing routes
app.post('/metrics/:id/media', authenticateToken, (req, res) => {
	const uploadHandler = upload.array('files', 10);
	uploadHandler(req, res, async (err) => {
		try {
			if (err) {
				return res.status(400).json({ error: err.message || 'Upload failed' });
			}

			const userId = req.user.userId;
			const metricId = parseInt(req.params.id, 10);

			// Verify metric ownership
			const userMetrics = await pool.query('SELECT * FROM metrics WHERE user_id = $1', [userId]);
			const target = (userMetrics.rows || []).find(m => m.id === metricId);
			if (!target) {
				return res.status(404).json({ error: 'Metric not found' });
			}

			const filesMeta = (req.files || []).map(f => {
				const timestamp = Date.now();
				const safeOriginal = f.originalname.replace(/[^a-zA-Z0-9_.-]/g, '_');
				const filename = `metric-${metricId}-user-${userId}-${timestamp}-${safeOriginal}`;
				const url = `${req.protocol}://${req.get('host')}/media/${timestamp}-${Math.random().toString(36).slice(2)}`; // temp, will be replaced after insert
				return {
					buffer: f.buffer,
					filename,
					originalname: f.originalname,
					mimetype: f.mimetype,
					size: f.size,
					url
				};
			});

			// Persist to DB and disk (best effort)
			const inserted = [];
			for (const f of filesMeta) {
				// Insert into DB with binary data only (no disk write)
				const row = await pool.query(
					'INSERT INTO media (user_id, metric_id, filename, originalname, mimetype, size, url, data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
					[userId, metricId, f.filename, f.originalname, f.mimetype, f.size, `${req.protocol}://${req.get('host')}/media/PLACEHOLDER`, f.buffer]
				);
				inserted.push(row.rows[0]);
			}
			
			// Replace URLs to point to DB streaming endpoint
			const files = inserted.map(m => ({
				...m,
				url: `${req.protocol}://${req.get('host')}/media/${m.id}/file`
			}));

			return res.status(201).json({ files });
		} catch (e) {
			console.error('Upload media error:', e);
			return res.status(500).json({ error: 'Internal server error' });
		}
	});
});

app.get('/metrics/:id/media', authenticateToken, async (req, res) => {
	try {
		const userId = req.user.userId;
		const metricId = parseInt(req.params.id, 10);

		// Verify metric ownership
		const userMetrics = await pool.query('SELECT * FROM metrics WHERE user_id = $1', [userId]);
		const target = (userMetrics.rows || []).find(m => m.id === metricId);
		if (!target) {
			return res.status(404).json({ error: 'Metric not found' });
		}

		// Read media from DB without binary data
		const media = await pool.query(
			'SELECT id, user_id, metric_id, filename, originalname, mimetype, size, url, created_at FROM media WHERE metric_id = $1 AND user_id = $2 ORDER BY created_at DESC',
			[metricId, userId]
		);
		const files = (media.rows || []).map(m => ({
			...m,
			url: `${req.protocol}://${req.get('host')}/media/${m.id}/file`
		}));
		return res.json({ files });
	} catch (e) {
		console.error('List media error:', e);
		return res.status(500).json({ error: 'Internal server error' });
	}
});

// Stream media file from DB
app.get('/media/:mediaId/file', authenticateToken, async (req, res) => {
	try {
		const userId = req.user.userId;
		const mediaId = parseInt(req.params.mediaId, 10);
		const result = await pool.query('SELECT * FROM media WHERE id = $1 AND user_id = $2', [mediaId, userId]);
		if (result.rows.length === 0) {
			return res.status(404).json({ error: 'Media not found' });
		}
		const media = result.rows[0];
		if (media.data) {
			res.setHeader('Content-Type', media.mimetype || 'application/octet-stream');
			if (media.size) {
				res.setHeader('Content-Length', media.size.toString());
			}
			return res.send(media.data);
		}
		return res.status(404).json({ error: 'Media data not available' });
	} catch (e) {
		console.error('Stream media error:', e);
		return res.status(500).json({ error: 'Internal server error' });
	}
});

// Add HEAD route to allow clients to probe media type/size without downloading
app.head('/media/:mediaId/file', authenticateToken, async (req, res) => {
	try {
		const userId = req.user.userId;
		const mediaId = parseInt(req.params.mediaId, 10);
		const result = await pool.query('SELECT id, user_id, mimetype, size FROM media WHERE id = $1 AND user_id = $2', [mediaId, userId]);
		if (result.rows.length === 0) {
			return res.status(404).end();
		}
		const media = result.rows[0];
		res.setHeader('Content-Type', media.mimetype || 'application/octet-stream');
		if (media.size) {
			res.setHeader('Content-Length', media.size.toString());
		}
		return res.status(200).end();
	} catch (e) {
		console.error('HEAD media error:', e);
		return res.status(500).end();
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