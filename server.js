import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env, { configDotenv } from "dotenv";

const app = express()
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))
const port = 3000
var isLoggedIn = false;
const saltRounds = 10;
env.config();
let currUser;
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: { maxAge: 1000 * 60 * 60 * 24 }
    })
);
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();



var posts = []
let lastId = 0;
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('home.ejs', { loggedIn: true })
    }
    else { res.render('home.ejs', { loggedIn: false }) }
})
app.get('/login', (req, res) => {
    res.render("login.ejs")
})
app.get("/register", (req, res) => {
    res.render("register.ejs");
});



app.post('/register', async (req, res) => {
    console.log(req.body)
    const email = req.body.email;
    const password = req.body.password;
    const username = req.body.username;
    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
            email,
        ]);

        if (checkResult.rows.length > 0) {
            res.redirect("/login");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    const result = await db.query(
                        "INSERT INTO users (username , email, password) VALUES ($1, $2 , $3) RETURNING *",
                        [username, email, hash]
                    );
                    const user = result.rows[0];
                    req.login(user, (err) => {
                        console.log("success");
                        isLoggedIn = true
                        res.redirect("/");

                    });
                }
            });
        }
    } catch (err) {
        console.log(err);
    }

})

app.post(
    "/login",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/login",
    })
);
app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.get('/create', (req, res) => {
    if (req.isAuthenticated())
        res.render('create.ejs', { loggedIn: true })
    else res.redirect('/login')
})
app.post('/create', async (req, res) => {
    const author = req.body.Author;
    const title = req.body.title;
    const concoct = req.body.concoct;
    const content = req.body.content;
    const id = currUser.id;
    console.log(content);
    const date = new Date().toLocaleDateString();
    const time = new Date().toLocaleTimeString();

    try {
        await db.query(
            `INSERT INTO posts (author, title, concoct, content, id, date_created, time_created) 
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [author, title, concoct, content, id, date, time]
        );
        res.redirect('/list');
    } catch (error) {
        console.log('Error inserting post:', error);
        res.status(500).send('Error creating post');
    }
})

app.get('/post/:id', async (req, res) => {
    try {
        const post = await getOnePost(parseInt(req.params.id))
        res.render('singlePost.ejs', { post: post, loggedIn: req.isAuthenticated(), currUser: currUser })

    } catch (error) {
        console.log(error)
    }
})
app.get('/list', async (req, res) => {
    try {
        const list = await getAllPosts()
        res.render('list.ejs', { posts: list, loggedIn: req.isAuthenticated(), currUser: currUser })
    } catch (error) {
        console.log(error)
    }
})

app.get('/myList', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const result = await getMyPosts()
            res.render('myList.ejs', { posts: result, loggedIn: req.isAuthenticated(), currUser: currUser })
        } catch (error) {
            console.log(error)
        }
    }
    else res.redirect('/login')
})

app.get('/edit-post/:id', async (req, res) => {
    if (req.isAuthenticated()) {

        try {
            const post = await db.query(
                `SELECT * FROM posts WHERE book_id = ${parseInt(req.params.id)}`
            )
            res.render('edit.ejs', { post: post.rows[0], loggedIn: req.isAuthenticated() })
        } catch (error) {
            console.log(error)
        }
    }
    else res.redirect('/login')
})

app.post('/edit', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const postId = req.body.post_id;
            const { title, author, concoct, content } = req.body;
            await db.query(
                `UPDATE posts SET author = $1, title = $2, content = $3, concoct = $4 WHERE book_id = $5`,
                [author, title, content, concoct, postId]
            );
            console.log('edited succesfully')
            res.redirect('/list')
        } catch (error) {
            console.log(error)
        }
    }
    else res.redirect('/login')

})
app.post('/modify', async (req, res) => {
    if (req.isAuthenticated()) {
        const action = req.body.action;
        const postId = req.body.post_id;
        if (action === 'edit') {
            res.redirect(`/edit-post/${postId}`);
        } else if (action === 'delete') {
            try {
                await db.query(
                    `DELETE FROM posts WHERE book_id = ${postId}`
                )
                console.log('deleted succesfully')
                res.redirect('/list');
            } catch (error) {
                console.log(error)
            }
        }
    }
    else res.redirect('/login')

});

async function getMyPosts() {
    const result = await db.query(
        `SELECT * FROM posts WHERE id = ${currUser.id}`
    )
    console.log(currUser.id)
    return result.rows
}
async function getAllPosts() {
    const result = await db.query(
        `SELECT * FROM posts`
    )
    return result.rows;
}

async function getOnePost(id) {
    const post = await db.query(
        `SELECT * FROM posts WHERE book_id = ${id}`
    )
    return post.rows[0]
}

passport.use(
    "local",
    new Strategy(async function verify(email, password, cb) {
        try {
            const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
                email,
            ]);
            if (result.rows.length > 0) {
                const user = result.rows[0];
                currUser = user;
                const storedHashedPassword = user.password;
                bcrypt.compare(password, storedHashedPassword, (err, valid) => {
                    if (err) {
                        console.error("Error comparing passwords:", err);
                        return cb(err);
                    } else {
                        if (valid) {
                            return cb(null, user);
                        } else {
                            return cb(null, false);
                        }
                    }
                });
            } else {
                return cb("User not found");
            }
        } catch (err) {
            console.log(err);
        }
    })
);


passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser((user, cb) => {
    cb(null, user);
});

app.listen(port, (req, res) => {
    console.log(`server on port ${port}`)
})



/*
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env, { configDotenv } from "dotenv";

const app = express()
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))
const port = 3000
// var isLoggedIn = false;  // ❌ REMOVED - security issue
const saltRounds = 10;
env.config();
// let currUser;  // ❌ REMOVED - security issue
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: { maxAge: 1000 * 60 * 60 * 24 }
    })
);
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

var posts = []
let lastId = 0;

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('home.ejs', { loggedIn: true, currUser: req.user })
    }
    else { res.render('home.ejs', { loggedIn: false, currUser: null }) }
})

app.get('/login', (req, res) => {
    res.render("login.ejs")
})

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.post('/register', async (req, res) => {
    console.log(req.body)
    const email = req.body.email;
    const password = req.body.password;
    const username = req.body.username;
    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
            email,
        ]);

        if (checkResult.rows.length > 0) {
            res.redirect("/login");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    const result = await db.query(
                        "INSERT INTO users (username , email, password) VALUES ($1, $2 , $3) RETURNING *",
                        [username, email, hash]
                    );
                    const user = result.rows[0];
                    req.login(user, (err) => {
                        console.log("success");
                        res.redirect("/");
                    });
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
})

app.post(
    "/login",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/login",
    })
);

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.get('/create', (req, res) => {
    if (req.isAuthenticated())
        res.render('create.ejs', { loggedIn: true, currUser: req.user })
    else res.redirect('/login')
})

app.post('/create', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    
    const author = req.body.Author;
    const title = req.body.title;
    const concoct = req.body.concoct;
    const content = req.body.content;
    const id = req.user.id;  // ✅ FIXED - using req.user.id
    console.log(content);
    const date = new Date().toLocaleDateString();
    const time = new Date().toLocaleTimeString();

    try {
        await db.query(
            `INSERT INTO posts (author, title, concoct, content, id, date_created, time_created) 
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [author, title, concoct, content, id, date, time]
        );
        res.redirect('/list');
    } catch (error) {
        console.log('Error inserting post:', error);
        res.status(500).send('Error creating post');
    }
})

app.get('/post/:id', async (req, res) => {
    try {
        const post = await getOnePost(parseInt(req.params.id))
        res.render('singlePost.ejs', { 
            post: post, 
            loggedIn: req.isAuthenticated(), 
            currUser: req.user || null
        })
    } catch (error) {
        console.log(error)
    }
})

app.get('/list', async (req, res) => {
    try {
        const list = await getAllPosts()
        res.render('list.ejs', { 
            posts: list, 
            loggedIn: req.isAuthenticated(), 
            currUser: req.user || null
        })
    } catch (error) {
        console.log(error)
    }
})

app.get('/myList', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const result = await getMyPosts(req.user.id)  // ✅ FIXED - passing req.user.id
            res.render('myList.ejs', { 
                posts: result, 
                loggedIn: req.isAuthenticated(), 
                currUser: req.user
            })
        } catch (error) {
            console.log(error)
        }
    }
    else res.redirect('/login')
})

app.get('/edit-post/:id', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const post = await db.query(
                `SELECT * FROM posts WHERE book_id = $1`,  // ✅ FIXED - SQL injection
                [parseInt(req.params.id)]
            )
            res.render('edit.ejs', { 
                post: post.rows[0], 
                loggedIn: req.isAuthenticated(),
                currUser: req.user
            })
        } catch (error) {
            console.log(error)
        }
    }
    else res.redirect('/login')
})

app.post('/edit', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const postId = req.body.post_id;
            const { title, author, concoct, content } = req.body;
            await db.query(
                `UPDATE posts SET author = $1, title = $2, content = $3, concoct = $4 WHERE book_id = $5`,
                [author, title, content, concoct, postId]
            );
            console.log('edited succesfully')
            res.redirect('/list')
        } catch (error) {
            console.log(error)
        }
    }
    else res.redirect('/login')
})

app.post('/modify', async (req, res) => {
    if (req.isAuthenticated()) {
        const action = req.body.action;
        const postId = req.body.post_id;
        if (action === 'edit') {
            res.redirect(`/edit-post/${postId}`);
        } else if (action === 'delete') {
            try {
                await db.query(
                    `DELETE FROM posts WHERE book_id = $1`,  // ✅ FIXED - SQL injection
                    [postId]
                )
                console.log('deleted succesfully')
                res.redirect('/list');
            } catch (error) {
                console.log(error)
            }
        }
    }
    else res.redirect('/login')
});

async function getMyPosts(userId) {  // ✅ FIXED - takes userId parameter
    const result = await db.query(
        `SELECT * FROM posts WHERE id = $1`,  // ✅ FIXED - SQL injection
        [userId]
    )
    return result.rows
}

async function getAllPosts() {
    const result = await db.query(
        `SELECT * FROM posts`
    )
    return result.rows;
}

async function getOnePost(id) {
    const post = await db.query(
        `SELECT * FROM posts WHERE book_id = $1`,  // ✅ FIXED - SQL injection
        [id]
    )
    return post.rows[0]
}

passport.use(
    "local",
    new Strategy(async function verify(email, password, cb) {
        try {
            const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
                email,
            ]);
            if (result.rows.length > 0) {
                const user = result.rows[0];
                // currUser = user;  // ❌ REMOVED - security issue
                const storedHashedPassword = user.password;
                bcrypt.compare(password, storedHashedPassword, (err, valid) => {
                    if (err) {
                        console.error("Error comparing passwords:", err);
                        return cb(err);
                    } else {
                        if (valid) {
                            return cb(null, user);
                        } else {
                            return cb(null, false);
                        }
                    }
                });
            } else {
                return cb("User not found");
            }
        } catch (err) {
            console.log(err);
        }
    })
);

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser((user, cb) => {
    cb(null, user);
});

app.listen(port, (req, res) => {
    console.log(`server on port ${port}`)
})
*/