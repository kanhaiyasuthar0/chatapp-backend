const express = require("express");
const mongoose = require("mongoose");
const http = require("http");

const bodyParser = require("body-parser");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
require("dotenv").config();
const socketIo = require("socket.io");
const app = express();
const cors = require("cors");
app.use(cors());

const multer = require('multer');
const upload = multer({ dest: 'uploads/' }); // This will save files to a folder named 'uploads'


const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000", // This should match the URL of your React app
    methods: ["GET", "POST"],
  },
});
console.log("🚀 ~ io:", io);
io.on("connection", (socket) => {
  console.log("A user connected");

  socket.on("disconnect", () => {
    console.log("User disconnected");
  });

  // Join a chat room
  socket.on('join chat', (chatRoom) => {
    socket.join(chatRoom);
    console.log(`User joined room: ${chatRoom}`);
  });
  socket.onAny((event, ...args) => {
    console.log(`Received event: ${event}, with data: ${JSON.stringify(args)}`);
  });

  socket.on('chat message', async (chatData) => {
    console.log("🚀 ~ socket.on ~ chatData:", chatData)
    const { chatRoom, encryptedMessage } = chatData;
   
     const newMessage = new ChatMessage({
        sender: encryptedMessage.sender,
        receiver: encryptedMessage.receiver,
        message: encryptedMessage.message,
        image: encryptedMessage.image 
      });
      await newMessage.save();
    
      // Broadcast the message
      // io.emit('chat message', encryptedMessage.message);
  
      io.to(chatRoom).emit('chat message', {
        message: encryptedMessage.message,
        image: encryptedMessage.image
      });
  })


  // Listen for chat messages
//   socket.on('chat message', async (encryptedMessage) => {
//     console.log("🚀 ~ socket.on ~ encryptedMessage:", encryptedMessage)
//     // Save the message to the database
//     const newMessage = new ChatMessage({
//       sender: encryptedMessage.sender,
//       receiver: encryptedMessage.receiver,
//       message: encryptedMessage.message
//     });
//     await newMessage.save();
  
//     // Broadcast the message
//     // io.emit('chat message', encryptedMessage.message);

//     io.to(chatRoom).emit('chat message', encryptedMessage.message);
//   });
});
const PORT = process.env.PORT || 3001;

console.log("🚀 ~ PORT:", process.env.PORT);

// Connect to MongoDB (Make sure you have MongoDB installed and running)
mongoose.connect(
  "mongodb+srv://kanhaiyasuthar0:eWcsMd2vEiFFx5Yn@chatcluster.k4flu4m.mongodb.net/chatapp",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

// Define a User model (you can extend this based on your needs)
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  publicKey: String,
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // Array of User IDs
});
const User = mongoose.model("User", UserSchema);

app.use('/uploads', express.static('uploads'));

const ChatMessageSchema = new mongoose.Schema({
    image: {type : String }, 
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: {
        nonce: String,
        encryptedMessage: String
    }, // Encrypted message
    timestamp: { type: Date, default: Date.now },
  });
  
  const ChatMessage = mongoose.model('ChatMessage', ChatMessageSchema);
  


// Middleware
app.use(bodyParser.json());
app.use(passport.initialize());

// Passport local strategy for username and password login
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username });

      if (!user) {
        return done(null, false, { message: "Incorrect username." });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return done(null, false, { message: "Incorrect password." });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

// Passport JWT strategy for token-based authentication
passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.SECRET_KEY || "secret_key", // Change this to a secure secret key
    },
    (payload, done) => {
      User.findById(payload.sub, (err, user) => {
        if (err) return done(err, false);
        if (user) return done(null, user);
        return done(null, false);
      });
    }
  )
);

app.get("/helloworld", (req, res) => {
  return res.send("Hello World!");
});

app.get("/api/users/:userId/public-key", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select("publicKey");
    if (!user) return res.status(404).send("User not found");
    res.json({ publicKey: user.publicKey });
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const { username, password, publicKey } = req.body;

    // Check if the username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists." });
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user with the public key
    const newUser = new User({
      username,
      password: hashedPassword,
      publicKey, // Save the public key
    });

    // Save the user to the database
    await newUser.save();

    return res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// to add a new friend
app.post("/api/users/:userId/add-friend", async (req, res) => {
  try {
    const userId = req.params.userId;
    const friendId = req.body.friendId; // ID of the friend to add

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send("User not found");
    }

    // Add friendId to the user's friends list if not already present
    if (!user.friends.includes(friendId)) {
      user.friends.push(friendId);
      await user.save();
    }

    res.status(200).send("Friend added successfully");
  } catch (error) {
    res.status(500).send("Server error");
  }
});

// to get the list of friends

app.get("/api/users/:userId/friends", async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId).populate(
      "friends",
      "username publicKey"
    );

    if (!user) {
      return res.status(404).send("User not found");
    }
    res.json(user.friends);
  } catch (error) {
    res.status(500).send("Server error");
  }
});


//API Endpoint to Fetch Chat History:
app.get('/api/chat/:userId/:friendId', async (req, res) => {
    try {
      const { userId, friendId } = req.params;
      const chatHistory = await ChatMessage.find({
        $or: [
          { sender: userId, receiver: friendId },
          { sender: friendId, receiver: userId }
        ]
      }).sort({ timestamp: 1 });
      res.json(chatHistory);
    } catch (error) {
      res.status(500).send('Server error');
    }
  });
  

app.post(
  "/api/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    // Generate a JWT token upon successful login
    const token = jwt.sign({ sub: req.user._id }, "your-secret-key", {
      expiresIn: "1h",
    });

    res.json({ token, userId : req.user._id  });
  }
);


// Endpoint to handle image uploads
app.post('/api/upload', upload.single('image'), async (req, res) => {
    try {
      // The file information will be in req.file
      console.log(req.file);
  
      // You should save the file info in your database and link it to the message
      // For example, save the file path and link it to the chat message
  
      res.status(200).json({ message: 'Image uploaded successfully', filePath: req.file.path });
    } catch (error) {
      res.status(500).send("Server error");
    }
  });
  

// Start the server
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
