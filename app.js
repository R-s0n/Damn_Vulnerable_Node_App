const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { execSync } = require('child_process');

const app = express();
app.use(express.json());

const upload = multer({ dest: 'uploads/' });

mongoose.connect('mongodb://127.0.0.1/demo', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
});

const hardcodedObject = {
    prop1: 'value1',
    prop2: 'value2',
    prop3: 'value3',
  };

const User = mongoose.model('User', userSchema);

app.post('/register', async (req, res) => {
  try {
    const { username, password, firstName, lastName, email } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      password: hashedPassword,
      firstName,
      lastName,
      email,
    });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while registering user' });
  }
});

app.post('/register/admin', async (req, res) => {
    try {
      const { username, password, firstName, lastName, email, secret } = req.body;
      if (secret !== 'supersecretapikeytoregisteranadmindonttellanyone') {
        return res.status(403).json({ error: 'Forbidden: Invalid secret key' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({
        username,
        password: hashedPassword,
        firstName,
        lastName,
        email,
        role: 'admin', 
      });
      await user.save();
      res.status(201).json({ message: 'Admin user registered successfully' });
    } catch (error) {
      res.status(500).json({ error: 'An error occurred while registering user' });
    }
  });

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const token = jwt.sign({ sub: user._id, role: user.role }, 'password', {
      algorithm: 'HS256',
      expiresIn: '24h'
    });
    res.json({ token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'An error occurred while logging in' });
  }
});

app.post('/upload', upload.single('file'), (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }
      const fileName = req.file.originalname;
      const filePath = path.join(__dirname, req.file.path);
      // Here, you can handle the file as needed, e.g., move it to the web root or save its metadata in the database.
      res.json({ message: 'File uploaded successfully', fileName, filePath });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while uploading the file' });
    }
  });

app.get('/users', async (req, res) => {
    try {
      const token = req.headers.authorization;
      console.log(token);
      if (!token) {
        return res.status(401).json({ error: 'Unauthorized: Missing token' });
      }
      const decodedToken = jwt.verify(token, 'password', {
        algorithms: ['HS256'],
      });

      if (decodedToken.role === 'user') {
        const nonAdminUsers = await User.find({ role: 'user' }).select('-password');
        return res.json(nonAdminUsers);
      } else {
        const users = await User.find().select('-password');
        res.json(users);
      }
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
});

app.get('/user/:id', async (req, res) => {
    try {
      const token = req.headers.authorization;
      if (!token) {
        return res.status(401).json({ error: 'Unauthorized: Missing token' });
      }
      const decodedToken = jwt.verify(token, 'password', {
        algorithms: ['HS256'],
      });
      if (decodedToken.role !== 'user') {
        return res.status(403).json({ error: 'Forbidden: User access required' });
      }
      const userId = req.params.id;
      const user = await User.findById(userId).select('-password');
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  });

app.post('/consolidate', (req, res) => {
    try {
      const userObject = req.body;
      const mergedObject = { ...hardcodedObject, ...userObject };
      res.json({ mergedObject });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while merging objects' });
    }
});

app.put('/user/admin/:id', async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: Missing token' });
    }
    const decodedToken = jwt.verify(token, 'password', {
      algorithm: 'HS256',
    });
    if (decodedToken.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
    const { id } = req.params;
    const { username, password, firstName, lastName, email, role } = req.body;
    const updatedUser = {
      username,
      firstName,
      lastName,
      email,
      role,
    };
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updatedUser.password = hashedPassword;
    }
    await User.findByIdAndUpdate(id, updatedUser);
    res.json({ message: 'User information updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while updating user information' });
  }
});

app.put('/user/:id', async (req, res) => {
    try {
      const token = req.headers.authorization;
      if (!token) {
        return res.status(401).json({ error: 'Unauthorized: Missing token' });
      }
      const decodedToken = jwt.verify(token, 'password', {
        algorithm: 'HS256',
      });
  
      const { id } = req.params;
      const { username, password, firstName, lastName, email, role } = req.body;
      const updatedUser = {
        username,
        firstName,
        lastName,
        email,
        role,
      };
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updatedUser.password = hashedPassword;
      }
      await User.findByIdAndUpdate(id, updatedUser);
      res.json({ message: 'User information updated successfully' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'An error occurred while updating user information' });
    }
  });

app.get('/debug', (req, res) => {
    try {
      const osInfo = execSync('uname -a').toString().trim();
      res.json({ operatingSystem: osInfo });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while fetching OS information' });
    }
});

app.put('/change-password/:id', async (req, res) => {
    try {
      const token = req.headers.authorization;
      if (!token) {
        return res.status(401).json({ error: 'Unauthorized: Missing token' });
      }
      const decodedToken = jwt.verify(token, 'password', {
        algorithms: ['HS256'],
      });
      const userId = req.params.id;
      const { currentPassword, newPassword } = req.body;
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isCurrentPasswordValid) {
        return res.status(401).json({ error: 'Invalid current password' });
      }
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedNewPassword;
      await user.save();
      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ error: 'Invalid token' });
      }
      console.error(error);
      res.status(500).json({ error: 'An error occurred while changing the password' });
    }
  });
  

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
