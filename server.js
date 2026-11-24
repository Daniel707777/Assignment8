const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { db, User, Project, Task } = require('./database/setup');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 1000 * 60 * 60 // 1 hour
    }
}));

// Authentication middleware
async function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Authentication required. Please log in.' });
    }

    try {
        const user = await User.findByPk(req.session.userId, {
            attributes: ['id', 'username', 'email']
        });

        if (!user) {
            return res.status(401).json({ error: 'User not found. Please log in again.' });
        }

        // Attach user info to the request for use in routes
        req.user = user;
        next();
    } catch (error) {
        console.error('Error in auth middleware:', error);
        res.status(500).json({ error: 'Authentication check failed' });
    }
}

// Test database connection
async function testConnection() {
    try {
        await db.authenticate();
        console.log('Connection to database established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}

testConnection();

// AUTH ROUTES

// POST /api/register - Create a new user account
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        // Make sure the email isn't already taken
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: 'A user with this email already exists' });
        }

        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            username,
            email,
            password: hashedPassword
        });

        res.status(201).json({
            message: 'User registered successfully',
            user: { id: newUser.id, username: newUser.username, email: newUser.email }
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// POST /api/login - Log in and start a session
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const passwordMatches = await bcrypt.compare(password, user.password);
        if (!passwordMatches) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Create the session
        req.session.userId = user.id;
        req.session.username = user.username;

        res.json({
            message: 'Login successful',
            user: { id: user.id, username: user.username, email: user.email }
        });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Failed to log in' });
    }
});

// POST /api/logout - End the session
app.post('/api/logout', (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            console.error('Error logging out:', error);
            return res.status(500).json({ error: 'Failed to log out' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logout successful' });
    });
});

// PROJECT ROUTES

// GET /api/projects - Get the logged-in user's projects (protected)
app.get('/api/projects', requireAuth, async (req, res) => {
    try {
        const projects = await Project.findAll({ where: { userId: req.user.id } });
        res.json(projects);
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});

// GET /api/projects/:id - Get project by ID
app.get('/api/projects/:id', async (req, res) => {
    try {
        const project = await Project.findByPk(req.params.id);
        
        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }
        
        res.json(project);
    } catch (error) {
        console.error('Error fetching project:', error);
        res.status(500).json({ error: 'Failed to fetch project' });
    }
});

// POST /api/projects - Create new project for the logged-in user (protected)
app.post('/api/projects', requireAuth, async (req, res) => {
    try {
        const { name, description, status, dueDate } = req.body;
        
        const newProject = await Project.create({
            name,
            description,
            status,
            dueDate,
            userId: req.user.id
        });
        
        res.status(201).json(newProject);
    } catch (error) {
        console.error('Error creating project:', error);
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// PUT /api/projects/:id - Update existing project
app.put('/api/projects/:id', async (req, res) => {
    try {
        const { name, description, status, dueDate } = req.body;
        
        const [updatedRowsCount] = await Project.update(
            { name, description, status, dueDate },
            { where: { id: req.params.id } }
        );
        
        if (updatedRowsCount === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }
        
        const updatedProject = await Project.findByPk(req.params.id);
        res.json(updatedProject);
    } catch (error) {
        console.error('Error updating project:', error);
        res.status(500).json({ error: 'Failed to update project' });
    }
});

// DELETE /api/projects/:id - Delete project
app.delete('/api/projects/:id', async (req, res) => {
    try {
        const deletedRowsCount = await Project.destroy({
            where: { id: req.params.id }
        });
        
        if (deletedRowsCount === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }
        
        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Error deleting project:', error);
        res.status(500).json({ error: 'Failed to delete project' });
    }
});

// TASK ROUTES

// GET /api/tasks - Get all tasks
app.get('/api/tasks', async (req, res) => {
    try {
        const tasks = await Task.findAll();
        res.json(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

// GET /api/tasks/:id - Get task by ID
app.get('/api/tasks/:id', async (req, res) => {
    try {
        const task = await Task.findByPk(req.params.id);
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        res.json(task);
    } catch (error) {
        console.error('Error fetching task:', error);
        res.status(500).json({ error: 'Failed to fetch task' });
    }
});

// POST /api/tasks - Create new task
app.post('/api/tasks', async (req, res) => {
    try {
        const { title, description, completed, priority, dueDate, projectId } = req.body;
        
        const newTask = await Task.create({
            title,
            description,
            completed,
            priority,
            dueDate,
            projectId
        });
        
        res.status(201).json(newTask);
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

// PUT /api/tasks/:id - Update existing task
app.put('/api/tasks/:id', async (req, res) => {
    try {
        const { title, description, completed, priority, dueDate, projectId } = req.body;
        
        const [updatedRowsCount] = await Task.update(
            { title, description, completed, priority, dueDate, projectId },
            { where: { id: req.params.id } }
        );
        
        if (updatedRowsCount === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        const updatedTask = await Task.findByPk(req.params.id);
        res.json(updatedTask);
    } catch (error) {
        console.error('Error updating task:', error);
        res.status(500).json({ error: 'Failed to update task' });
    }
});

// DELETE /api/tasks/:id - Delete task
app.delete('/api/tasks/:id', async (req, res) => {
    try {
        const deletedRowsCount = await Task.destroy({
        where: { id: req.params.id }
        });
        
        if (deletedRowsCount === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        res.json({ message: 'Task deleted successfully' });
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port http://localhost:${PORT}`);
});
