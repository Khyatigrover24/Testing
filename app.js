const express = require('express');
const ErrorHandler = require('./utils/errorHandler');
const handleErrors = require('./middlewares/error');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const passport = require('passport');
const session = require('express-session');
const cookieParser = require('cookie-parser');

dotenv.config({ path: './config/config.env' });

const app = express();

const allowedOrigins = [
    'http://localhost:5173',
    'https://theassigner.com',
    'https://www.theassigner.com'
];

const corsOptions = {
    origin: function (origin, callback) {
        if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: 'GET,POST,PUT,DELETE',
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

app.use(cors(corsOptions));

const limiter = rateLimit({
    max: 100,
    windowMs: 60 * 60 * 1000,
    message: 'Too many requests from this IP, please try again in an hour!'
});
app.use('/api', limiter);
app.use(bodyParser.json());


app.use(session({
    secret: '111',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Change to true if using https
}));

app.use(passport.initialize());
app.use(passport.session());

const user = require('./routes/userRoute');
const admin = require('./routes/adminRoute');
const assignment = require('./routes/assignmentRoute');
const resume = require('./routes/resumeRoute');
const contact = require('./routes/contactRoute');
const job = require('./routes/jobRoute');
const subscribe = require('./routes/SubscriberEmailRoute');
const pdf = require('./routes/PDFRoute');
const thesis = require('./routes/thesisRoute');
const dissertation = require('./routes/dissertationRoute');
const blog = require('./routes/blogRoute');
const applicant = require('./routes/applicantRoute');
const ielts = require("./routes/ieltsUserRoute");

app.use(express.json());

// require to parse cookies
// const cookieParser = require('cookie-parser');

app.use('/api/v1/user', user);
app.use('/api/v1/admin', admin);
app.use('/api/v1/assignments', assignment);
app.use('/api/v1/contacts', contact);
app.use('/api/v1/job', job);
app.use('/api/v1/subscribe', subscribe);
app.use('/api/v1/pdf', pdf);
app.use('/api/v1/resumes', resume);
app.use('/api/v1/theses', thesis);
app.use('/api/v1/dissertations', dissertation);
app.use('/api/v1/blogs', blog);
app.use('/api/v1/applicants', applicant);
app.use('/api/v1/ielts', ielts);

app.use(cookieParser());


app.use('/', function (req, res) {
    res.json({ connected: 'assigner 02' })
})

app.all('*', (req, res, next) => {
    next(new ErrorHandler(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(handleErrors);

module.exports = app;