

Step - by - Step Implementation

Step 1: Define Roles and Permissions

backend / config / roles.js

const ROLES = {
    STUDENT: 'student', TEACHER: 'teacher', MODERATOR:
        'moderator', ADMIN: 'admin'
}; const PERMISSIONS = {
    student: ['join_class',
        'view_own_attendance', 'scan_qr'], teacher: ['create_class', 'end_class',
            'view_own_classes', 'generate_qr', 'manage_attendance', 'join_class', //
            Teachers can also join as students 'view_own_attendance'], moderator: [
                'create_class', 'end_class', 'view_own_classes', 'manage_divisions',
                'move_students', 'view_all_divisions', 'bulk_operations'], admin: [
                    'manage_users', 'create_users', 'delete_users', 'system_settings',
                    'view_all_data', 'export_reports', 'manage_divisions', // Inherit moderator
                    permissions 'create_class', // Inherit teacher permissions 'view_everything'
                ]
}; // Function to get user permissions 
const getUserPermissions = (role) =>
{ return PERMISSIONS[role] || []; }; // Function to check if user has specific permission 
const hasPermission = (userRole, permission) => {
    const
        userPermissions = getUserPermissions(userRole); return
    userPermissions.includes(permission);
}; module.exports = {
    ROLES,
    PERMISSIONS, getUserPermissions, hasPermission
};








Step 2: User Model with Roles

backend / models / User.js

const mongoose = require('mongoose'); const bcrypt = require('bcryptjs');
const userSchema = new mongoose.Schema({
    email: {
        type: String, required:
            true, unique: true, lowercase: true
    }, password: {
        type: String, required:
            true
    }, name: { type: String, required: true }, role: {
        type: String, enum:
            ['student', 'teacher', 'moderator', 'admin'], required: true
    }, usn: {
        type:
            String, // CS001, CS002 etc for students sparse: true // Only required for
        students
    }, division_id: {
        type: mongoose.Schema.Types.ObjectId, ref:
            'Division', required: function () { return this.role === 'student'; }
    },
    assigned_divisions: [{ // For teachers - which divisions they can teach type:
        mongoose.Schema.Types.ObjectId, ref: 'Division'
    }], created_at: {
        type: Date,
        default: Date.now
    }
}); // Hash password before saving userSchema.pre('save',
async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12); next();
}); // Compare
password method userSchema.methods.comparePassword = async function (password) { return await bcrypt.compare(password, this.password); }; module.exports =
    mongoose.model('User', userSchema);






Step 3: Division Model

backend / models / Division.js

const mongoose = require('mongoose'); const divisionSchema = new
    mongoose.Schema({
        name: {
            type: String, required: true // "A Division", "B
Division", etc. }, code: { type: String, required: true, unique: true //
"DIV_A", "DIV_B", etc. }, division_start: {
            type: Number, required: true,
            default: 1
        }, division_end: { type: Number, required: true, default: 60 },
        current_strength: { type: Number, default: 0 }, academic_year: {
            type:
                String, required: true // "2024-25" }, department: { type: String, required:
true // "Computer Science" }, created_at: { type: Date, default: Date.now }
}); module.exports = mongoose.model('Division', divisionSchema);

Step 4: Authentication Middleware

backend / middleware / auth.js

const jwt = require('jsonwebtoken'); const User = require('../models/User');
const { hasPermission } = require('../config/roles'); // Verify JWT token and
get user const authenticate = async (req, res, next) => {
    try {
        const token =
            req.header('Authorization')?.replace('Bearer ', ''); if (!token) {
                return
                res.status(401).json({ error: 'Access denied. No token provided.' });
            } const
                decoded = jwt.verify(token, process.env.JWT_SECRET); const user = await
                    User.findById(decoded.id).populate('division_id assigned_divisions'); if
            (!user) { return res.status(401).json({ error: 'Invalid token.' }); }
        req.user = user; next();
    } catch (error) {
        res.status(401).json({
            error:
                'Invalid token.'
        });
    }
}; // Check if user has required permission const
requirePermission = (permission) => {
    return (req, res, next) => {
        if
            (!req.user) {
            return res.status(401).json({
                error: 'Authentication required'
            });
        } if (!hasPermission(req.user.role, permission)) {
            return
            res.status(403).json({
                error: 'Insufficient permissions', required:
                    permission, userRole: req.user.role
            });
        } next();
    };
}; // Check multiple
permissions(user must have ALL) const requireAllPermissions = (permissions)
    => {
    return (req, res, next) => {
        const hasAllPermissions =
            permissions.every(permission => hasPermission(req.user.role, permission));
        if (!hasAllPermissions) {
            return res.status(403).json({
                error: 'Insufficient
permissions', required: permissions, userRole: req.user.role }); } next(); };
}; // Check if user has ANY of the required permissions const
            requireAnyPermission = (permissions) => {
                return (req, res, next) => {
                    const
                        hasAnyPermission = permissions.some(permission =>
                            hasPermission(req.user.role, permission)); if (!hasAnyPermission) {
                                return
                                res.status(403).json({
                                    error: 'Insufficient permissions', required: `One of:
${permissions.join(', ')}`, userRole: req.user.role
                                });
                            } next();
                };
            };
            module.exports = {
                authenticate, requirePermission, requireAllPermissions,
                requireAnyPermission
            };

            file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 3/14



            9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

Step 5: Authentication Routes

            backend / routes / auth.js

            const express = require('express'); const jwt = require('jsonwebtoken');
            const User = require('../models/User'); const { authenticate } =
                require('../middleware/auth'); const router = express.Router(); // Login
            route - handles all roles router.post('/login', async (req, res) => {
                try {
                    const { email, password } = req.body; // Find user by email const user =
                    await User.findOne({ email }).populate('division_id assigned_divisions'); if
                        (!user) {
                        return res.status(400).json({
                            error: 'Invalid email or password'
                        });
                    } // Check password const isMatch = await user.comparePassword(password);
                    if (!isMatch) {
                        return res.status(400).json({
                            error: 'Invalid email or
password' }); } // Generate JWT token with user role const token = jwt.sign(
{ id: user._id, role: user.role, email: user.email }, process.env.JWT_SECRET,
{ expiresIn: '24h' }); // Send response with user data and role res.json({
                        success: true, token, user: {
                            id: user._id, name: user.name, email:
                            user.email, role: user.role, usn: user.usn, division: user.division_id,
                                assigned_divisions: user.assigned_divisions
                        }
                    });
        } catch (error) {
            console.error(error); res.status(500).json({ error: 'Server error' });
        }
    });
    // Get current user info router.get('/me', authenticate, (req, res) => {
    res.json({
        user: {
            id: req.user._id, name: req.user.name, email:
                req.user.email, role: req.user.role, usn: req.user.usn, division:
                req.user.division_id, assigned_divisions: req.user.assigned_divisions
        }
    });
}); // Logout (if you want to implement token blacklisting)
router.post('/logout', authenticate, (req, res) => { // In a more complex
    setup, you'd blacklist the token res.json({ success: true, message: 'Logged
out successfully' }); }); module.exports = router;

Step 6: Protected Routes Examples

    backend / routes / teacher.js

    file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 4/14



    9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

    const express = require('express'); const { authenticate, requirePermission }
        = require('../middleware/auth'); const router = express.Router(); // Only
teachers can create class sessions router.post('/create-session',
            authenticate, requirePermission('create_class'), async (req, res) => {
                try {
                    // Create class session logic here const { division_id, subject } = req.body;
                    // Check if teacher is assigned to this division if
                    (!req.user.assigned_divisions.includes(division_id)) {
                        return
                        res.status(403).json({ error: 'Not authorized for this division' });
                    } //
Create session logic here...res.json({
                        success: true, message: 'Session
created' }); } catch (error) { res.status(500).json({ error: 'Server error'
});
} }); // Get teacher's assigned divisions router.get('/my-divisions',
authenticate, requirePermission('view_own_classes'), async (req, res) => {
    try {
        const divisions = req.user.assigned_divisions; res.json({ divisions });
    } catch (error) { res.status(500).json({ error: 'Server error' }); }
} );
module.exports = router;

backend / routes / student.js

const express = require('express'); const { authenticate, requirePermission }
    = require('../middleware/auth'); const router = express.Router(); // Only
students can join class sessions router.post('/join-session', authenticate,
        requirePermission('join_class'), async (req, res) => {
            try {
                const {
                    session_id, qr_data } = req.body; // Verify student belongs to the session's
                division // Join session logic here... res.json({ success: true, message:
                'Joined session successfully'
            }); } catch (error) {
                res.status(500).json({
                    error: 'Server error'
                });
            } } ); // Get active sessions for student's
division only router.get('/active-sessions', authenticate,
                requirePermission('view_own_attendance'), async (req, res) => {
                    try {
                        const
                            studentDivision = req.user.division_id; // Get active sessions for this
division only // const activeSessions = await Session.find({ division_id:
                        studentDivision, status: 'active'
                    }); res.json({ sessions: [] }); // Replace
with actual sessions } catch (error) {
    res.status(500).json({
        error: 'Server
error' }); } } ); module.exports = router;

Step 7: Frontend Permission Utils

frontend/ src / utils / permissions.js

file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 5/14



        9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

const PERMISSIONS = {
        student: ['join_class', 'view_own_attendance',
            'scan_qr'], teacher: ['create_class', 'end_class', 'view_own_classes',
                'generate_qr', 'manage_attendance'], moderator: ['create_class',
                    'end_class', 'manage_divisions', 'move_students', 'view_all_divisions'],
        admin: ['manage_users', 'system_settings', 'view_all_data',
            'manage_divisions', 'create_class']
    }; // Check if user has permission
    export const canUserAccess = (userRole, feature) => {
        const userPermissions =
            PERMISSIONS[userRole] || []; return userPermissions.includes(feature);
    }; //
Check multiple permissions export const hasAllPermissions = (userRole,
        features) => {
        return features.every(feature => canUserAccess(userRole,
            feature));
    }; // Check any permission export const hasAnyPermission =
    (userRole, features) => {
        return features.some(feature =>
            canUserAccess(userRole, feature));
    }; // Get user's dashboard route based on
role export const getDashboardRoute = (role) => {
        const routes = {
            student:
                '/student-dashboard', teacher: '/teacher-dashboard', moderator: '/moderator-
dashboard', admin: '/admin-dashboard' }; return routes[role] || '/'; };

Step 8: React Login Component

frontend/ src / components / Login.jsx

        file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 6/14



        9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

        import { useState } from 'react'; import { useNavigate } from 'react-router-
dom'; import { getDashboardRoute } from '../ utils / permissions'; const Login =
            ({ setUser }) => {
        const [email, setEmail] = useState(''); const [password,
            setPassword] = useState(''); const [loading, setLoading] = useState(false);
        const [error, setError] = useState(''); const navigate = useNavigate(); const
            handleSubmit = async (e) => {
                e.preventDefault(); setLoading(true);
                setError(''); try {
                    const response = await fetch('/api/auth/login', {
                        method:
                            'POST', headers: { 'Content-Type': 'application/json' }, body:
                            JSON.stringify({ email, password })
                    }); const data = await response.json();
                    if (response.ok) { // Store token and user data localStorage.setItem('token',
                        data.token); localStorage.setItem('user', JSON.stringify(data.user)); // Set
                        user in app state setUser(data.user); // Redirect to appropriate dashboard
based on role const dashboardRoute = getDashboardRoute(data.user.role);
                        navigate(dashboardRoute);
                    } else { setError(data.error || 'Login failed'); }
                } catch (error) { setError('Network error. Please try again.'); } finally {
                    setLoading(false);
                }
            }; return (

                Attendance System Login

        {
            error &&
                { error }
        }

        Email: { email } setEmail(e.target.value)
    } required
    placeholder = "Enter your email" />

        Password: ••••••••••  setPassword(e.target.value)
} required
placeholder = "Enter your password" />

    { loading? 'Logging in...': 'Login' }
); }; export default Login;

Step 9: Role - Based Dashboard Components

frontend / src / components / TeacherDashboard.jsx

file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 7/14



9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

import { useState, useEffect } from 'react'; import { canUserAccess } from
    '../utils/permissions'; const TeacherDashboard = ({ user }) => {
        const
            [divisions, setDivisions] = useState([]); const [selectedDivision,
                setSelectedDivision] = useState(''); useEffect(() => { fetchMyDivisions(); },
                    []); const fetchMyDivisions = async () => {
                        try {
                            const response = await
                                fetch('/api/teacher/my-divisions', {
                                    headers: {
                                        'Authorization': `Bearer
${localStorage.getItem('token')}`
                                    }
                                }); const data = await response.json();
                            setDivisions(data.divisions || []);
                        } catch (error) {
                            console.error('Failed
to fetch divisions'); } }; const createSession = async (subject) => { if
                                (!selectedDivision) { alert('Please select a division first'); return; } try {
                                    const response = await fetch('/api/teacher/create-session', {
                                        method:
                                            'POST', headers: {
                                                'Content-Type': 'application/json', 'Authorization':
                                                    `Bearer ${localStorage.getItem('token')}`
                                            }, body: JSON.stringify({
                                                division_id: selectedDivision, subject
                                            })
                                    }); if (response.ok) {
                                        alert('Session created successfully!');
                                    }
                                } catch (error) {
                                    alert('Failed to
create session'); } }; return (

Welcome, { user.name }
Role: Teacher

{ canUserAccess(user.role, 'create_class') && (

                                            Start Class Session

Select Division: Choose Division...
                                    createSession('Mathematics')
                                }> Start Math Class
                            createSession('Physics')
                        }> Start Physics Class
                        createSession('Chemistry')
                    }> Start Chemistry Class

)} {
    canUserAccess(user.role, 'view_own_classes') && (

        My Class Analytics

    {/* Analytics components here */ }
)
}
); }; export default TeacherDashboard;

frontend / src / components / StudentDashboard.jsx

file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 8/14



9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

import { useState, useEffect } from 'react'; import { canUserAccess } from
    '../utils/permissions'; const StudentDashboard = ({ user }) => {
        const
            [activeSessions, setActiveSessions] = useState([]); useEffect(() => {
                fetchActiveSessions();
            }, []); const fetchActiveSessions = async () => {
                try {
                    const response = await fetch('/api/student/active-sessions', {
                        headers: {
                            'Authorization': `Bearer ${localStorage.getItem('token')}`
                        }
                    }); const data =
                        await response.json(); setActiveSessions(data.sessions || []);
                } catch
                (error) { console.error('Failed to fetch active sessions'); }
            }; const
                joinSession = async (sessionId) => { // This would typically open QR scanner
                    try {
                        const response = await fetch('/api/student/join-session', {
                            method:
                                'POST', headers: {
                                    'Content-Type': 'application/json', 'Authorization':
                                        `Bearer ${localStorage.getItem('token')}`
                                }, body: JSON.stringify({
                                    session_id: sessionId, qr_data: 'scanned_qr_data' // This would come from QR
scanner
                                })
                        }); if (response.ok) { alert('Attendance marked successfully!'); }
                    } catch (error) { alert('Failed to join session'); }
                }; return (

                    Welcome, { user.name }
USN: { user.usn }

        Division: { user.division?.name }

        {
            canUserAccess(user.role, 'join_class') && (

                Active Classes for Your Division

{
                    activeSessions.length > 0 ? (activeSessions.map(session => (

                        { session.subject }

Teacher: { session.teacher_name }

Started: { new Date(session.start_time).toLocaleTimeString() }

joinSession(session._id)} > Join Class(Scan QR)
)) ) : (

    No active classes at the moment

)}
)} {
    canUserAccess(user.role, 'view_own_attendance') && (

        My Attendance History

    {/* Attendance history components here */ }
)
}

file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 9/14



9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

); }; export default StudentDashboard;

Step 10: Main App with Role - Based Routing

frontend / src / App.jsx

import { useState, useEffect } from 'react'; import {
    BrowserRouter as
        Router, Routes, Route, Navigate
} from 'react-router-dom'; import Login from
    './components/Login'; import TeacherDashboard from
    './components/TeacherDashboard'; import StudentDashboard from
    './components/StudentDashboard'; import ModeratorDashboard from
    './components/ModeratorDashboard'; import AdminDashboard from
    './components/AdminDashboard'; const App = () => {
        const [user, setUser] =
            useState(null); const [loading, setLoading] = useState(true); useEffect(() => { // Check if user is already logged in const token =
                localStorage.getItem('token'); const userData = localStorage.getItem('user');
                if (token && userData) {
                    try {
                        const parsedUser = JSON.parse(userData);
                        setUser(parsedUser);
                    } catch (error) {
                        localStorage.removeItem('token');
                        localStorage.removeItem('user');
                    }
                } setLoading(false);
            }, []); const logout
                = () => {
                    localStorage.removeItem('token'); localStorage.removeItem('user');
                    setUser(null);
                }; if (loading) {
                    return
Loading...
                    ;
                } // Protected Route Component const ProtectedRoute = ({ children,
        allowedRoles
    }) => {
    if (!user) { return; } if (allowedRoles &&
        !allowedRoles.includes(user.role)) { return; } return children;
}; return (
    { user && (

        Welcome, { user.name }({ user.role }) Logout
)} {/* Public Routes */ } : } /> {/ * Protected Role - Based Routes * /} } / > } />
} /> } / > {/* Default Routes */ } : } /> Unauthorized Access
} />

); }; export default App;

Permission Check Examples

Frontend Permission Checks

file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 10/14



9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

import { canUserAccess } from '../utils/permissions'; // Example usage in any
component const SomeComponent = ({ user }) => {
    return (
        {/* Show create button only to teachers */ } {
        canUserAccess(user.role,
            'create_class') && (Create Class  )
    } {/* Show join button only to students

*/} { canUserAccess(user.role, 'join_class') && (Join Class  ) } {/* Show admin
panel only to admins */} {
        canUserAccess(user.role, 'manage_users') && (

            Manage Users  System Settings
)} {/* Show division management to moderators and admins */ }
{ (canUserAccess(user.role, 'manage_divisions')) && (Manage Divisions  ) }
); };

Backend Route Protection Examples

const express = require('express'); const { authenticate, requirePermission,
    requireAnyPermission } = require('../middleware/auth'); const router =
        express.Router(); // Only students can scan QR codes router.post('/scan-qr',
authenticate, requirePermission('scan_qr'), (req, res) => { // QR scanning
    logic
} ); // Only teachers can generate QR codes router.post('/generate-qr',
authenticate, requirePermission('generate_qr'), (req, res) => { // QR
generation logic
} ); // Both moderators and admins can manage divisions
router.put('/manage-division/:id', authenticate,
    requirePermission('manage_divisions'), (req, res) => { // Division management
        logic
    }); // Only admins can manage users router.post('/create-user',
authenticate, requirePermission('manage_users'), (req, res) => { // User
creation logic
} );

Testing Your RBAC Implementation

Create Test Users

// Create test users with different roles const testUsers = [ { email:
'student@college.edu', password: 'password123', name: 'John Student', role:
'student', usn: 'CS001', division_id: divisionId }, {
    email:
    'teacher@college.edu', password: 'password123', name: 'Jane Teacher', role:
    'teacher', assigned_divisions: [divisionId]
}, {
    email:
    'moderator@college.edu', password: 'password123', name: 'Bob Moderator',
        role: 'moderator'
}, {
    email: 'admin@college.edu', password: 'password123',
        name: 'Alice Admin', role: 'admin'
} ];

file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 11/14



9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

Test Cases to Verify

✅ Authentication Tests
Login with student credentials → Redirected to student dashboard
Login with teacher credentials → Redirected to teacher dashboard
Login with moderator credentials → Redirected to moderator dashboard
Login with admin credentials → Redirected to admin dashboard

✅ Authorization Tests
Student cannot access teacher routes
Teacher cannot access admin routes
Only students can join classes
Only teachers can create classes
Only moderators / admins can manage divisions
Only admins can manage users

Environment Variables

    .env

# Database MONGODB_URI = mongodb://localhost:27017/attendance_system # JWT
Secret(use a strong secret in production)
JWT_SECRET = your_super_secret_jwt_key_here_make_it_long_and_random # Server
Port PORT = 5000 # Frontend URL(for CORS) FRONTEND_URL = http://localhost:3000

Quick Implementation Checklist

Step File Status Description

1 config / roles.js ☐ Define all roles and permissions

2 models / User.js ☐ User schema with role field

file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 12/14



9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

Step File Status Description

3 models / Division.js ☐ Division schema for class management

4 middleware / auth.js ☐ JWT authentication + permission checks

5 routes / auth.js ☐ Login route with role detection

6 routes / teacher.js ☐ Teacher - only protected routes

7 routes / student.js ☐ Student - only protected routes

8 utils / permissions.js ☐ Frontend permission checking

9 components / Login.jsx ☐ Single login form with role routing

10 App.jsx ☐ Role - based routing setup

🚀 Quick Start Commands

# Backend setup cd backend npm init - y npm install express mongoose
bcryptjs jsonwebtoken cors dotenv npm install - D nodemon # Frontend
setup cd../ frontend npx create - react - app.npm install react - router - dom
# Start development # Terminal 1: Backend npm run dev # Terminal 2:
Frontend npm start

🔥 Common Pitfalls to Avoid
JWT Secret: Use a strong, random secret in production
Token Expiry: Handle token expiration gracefully
Role Validation: Always validate roles on both frontend AND backend
Permission Sync: Keep frontend and backend permissions in sync
Error Handling: Provide clear error messages for permission denials
Database Indexes: Add indexes on email and role fields

file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 13/14



9 / 20 / 25, 11: 44 AM RBAC Implementation Guide - Complete Reference

This guide provides everything you need to implement a complete RBAC system from scratch.Copy the code, follow the
steps, and customize as needed for your attendance system!

file:///C:/Users/tubac/Downloads/rbac_implementation_guide.html 14/14