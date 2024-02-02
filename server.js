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

const multer = require("multer");
const upload = multer({ dest: "uploads/" }); // This will save files to a folder named 'uploads'

const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    // origin: "http://localhost:3000", // This should match the URL of your React app
    origin: "https://chatapp-weld-three.vercel.app", // This should match the URL of your React app
    methods: ["GET", "POST"],
  },
});
console.log("🚀 ~ io:", io);
io.on("connection", (socket) => {
  console.log("A user connected");
  console.log(`New client connected with socket ID: ${socket.id}`);

  socket.on("disconnect", () => {
    console.log("User disconnected");
  });

  // Join a chat room
  socket.on("join chat", (chatRoom) => {
    socket.join(chatRoom);
    console.log(`User joined room: ${chatRoom}`);
  });
  socket.onAny((event, ...args) => {
    console.log(`Received event: ${event}, with data: ${JSON.stringify(args)}`);
  });

  socket.on("chat message", async (chatData) => {
    console.log("🚀 ~ socket.on ~ chatData:", chatData);
    const { chatRoom, encryptedMessage } = chatData;

    const newMessage = new ChatMessage({
      sender: encryptedMessage.sender,
      receiver: encryptedMessage.receiver,
      message: encryptedMessage.message,
      image: encryptedMessage.image,
    });
    await newMessage.save();

    // Broadcast the message
    // io.emit('chat message', encryptedMessage.message);

    io.to(chatRoom).emit("chat message", {
      message: encryptedMessage.message,
      image: encryptedMessage.image,
      sender: encryptedMessage.sender,
      receiver: encryptedMessage.receiver,
    });
  });

  // Video call
  // console.log("before call");
  socket.on("sending signal", ({ userToSignal, signal, callerID }) => {
    console.log("call user to:", userToSignal);
    // console.log("signalData:", signal);
    io.to(userToSignal).emit("incoming call", {
      signal: signal,
      from: callerID,
    });
  });

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
  username: {
    type: String,
    unique: true, // This ensures that the username is unique in the database
    required: true,
  },
  mobile: {
    type: Number,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  publicKey: {
    type: String,
    required: true,
  }, // Known bug: Adding strict type checkings to ensure the required field and uniqueness of the entries
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // Array of User IDs
});
const User = mongoose.model("User", UserSchema);

app.use("/uploads", express.static("uploads"));

const ChatMessageSchema = new mongoose.Schema({
  image: { type: String },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  message: {
    nonce: String,
    encryptedMessage: String,
  }, // Encrypted message
  timestamp: { type: Date, default: Date.now },
});

const ChatMessage = mongoose.model("ChatMessage", ChatMessageSchema);

// Middleware
app.use(bodyParser.json());
app.use(passport.initialize());

// Passport local strategy for username and password login
// passport.use(
//   new LocalStrategy(async (username, password, done) => {
//     try {
//       const user = await User.findOne({ username });

//       if (!user) {
//         return done(null, false, { message: "Incorrect username." });
//       }

//       const passwordMatch = await bcrypt.compare(password, user.password);

//       if (!passwordMatch) {
//         return done(null, false, { message: "Incorrect password." });
//       }

//       // / Extract publicKey from the request body
//       const req = this.passport?._request;
//       console.log("🚀 ~ newLocalStrategy ~ req:", req)
//       const publicKey = req?.body?.publicKey;
//       console.log("🚀 ~ newLocalStrategy ~ publicKey:", publicKey)
//       console.log("🚀 ~ newLocalStrategy ~ new:", user.publicKey)

//       if (publicKey) {
//         // Update the publicKey for the user
//         user.publicKey = publicKey;
//         await user.save();
//       }

//       return done(null, user);
//     } catch (error) {
//       return done(error);
//     }
//   })
// );

passport.use(
  new LocalStrategy(
    {
      usernameField: "username",
      passwordField: "password",
      passReqToCallback: true,
    },
    async (req, username, password, done) => {
      try {
        const user = await User.findOne({ username });

        if (!user) {
          return done(null, false, { message: "Incorrect username." });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
          return done(null, false, { message: "Incorrect password." });
        }

        // // Extract publicKey from the request body
        // const publicKey = req.body.publicKey;
        // console.log("🚀 ~ publicKey:", publicKey)

        // if (publicKey) {
        //   // Update the publicKey for the user
        //   user.publicKey = publicKey;
        //   await user.save();
        // }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
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
// known bugs which handles atomicity
app.post("/api/register", async (req, res) => {
  const session = await mongoose.startSession(); // Start a session for the transaction
  session.startTransaction(); // Start the transaction

  try {
    const { username, password, publicKey, mobile } = req.body;

    // Check if the username already exists within the transaction
    const existingUser = await User.findOne({ username }).session(session);
    if (existingUser) {
      await session.abortTransaction(); // Abort the transaction if username exists
      return res.status(400).json({ message: "Username already exists." });
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user with the public key
    const newUser = new User({
      username,
      password: hashedPassword,
      publicKey,
      mobile,
    });

    // Save the user to the database within the transaction
    await newUser.save({ session });

    await session.commitTransaction(); // Commit the transaction
    session.endSession(); // End the session

    return res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    await session.abortTransaction(); // Abort the transaction on error
    session.endSession(); // End the session
    console.error(error);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// to add a new friend
// known bug : Adding a friend using can be improvised to mobile number which the other can easily have access to and also once added in the one friend side it can be added to other side as well.
app.post("/api/users/:userId/add-friend", async (req, res) => {
  try {
    const userId = req.params.userId;
    const friendId = req.body.friendId; // ID of the friend to add

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send("User not found");
    }
    if (friendId == user.mobile) {
      return res.status(404).send("Cannot add own number");
    }

    // Find the friend by mobile number
    const friend = await User.findOne({ mobile: friendId });
    if (!friend) {
      return res.status(404).send("Friend not found");
    }

    if (!user.friends.includes(friend._id)) {
      user.friends.push(friend._id);
      friend.friends.push(user._id);
      await user.save();
      await friend.save();
      res.status(200).send("Friend added successfully");
    } else {
      res.status(200).send("Friend already in friends list");
    }

    // // Add friendId to the user's friends list if not already present
    // if (!user.friends.includes(friendId)) {
    //   user.friends.push(friendId);
    //   await user.save();
    // }

    // res.status(200).send("Friend added successfully");
  } catch (error) {
    res.status(500).send("Server error");
  }
});

// to get the list of friends : Known bugs : Here I want to send the id as well or mobile number of friend and also I can send the public key so that extra get call at friend can be easily avoided.
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
app.get("/api/chat/:userId/:friendId", async (req, res) => {
  try {
    const { userId, friendId } = req.params;
    const chatHistory = await ChatMessage.find({
      $or: [
        { sender: userId, receiver: friendId },
        { sender: friendId, receiver: userId },
      ],
    }).sort({ timestamp: 1 });
    res.json(chatHistory);
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.post(
  "/api/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    console.log("🚀 ~ req:", req.user);
    // Generate a JWT token upon successful login
    const token = jwt.sign({ sub: req.user._id }, "your-secret-key", {
      expiresIn: "1h",
    });

    res.json({
      token,
      userId: req.user._id,
      publicKey: req.user.publicKey,
      username: req.user.username,
    });
  }
);

// Endpoint to handle image uploads
app.post("/api/upload", upload.single("image"), async (req, res) => {
  try {
    // The file information will be in req.file
    console.log(req.file);

    // You should save the file info in your database and link it to the message
    // For example, save the file path and link it to the chat message

    res.status(200).json({
      message: "Image uploaded successfully",
      filePath: req.file.path,
    });
  } catch (error) {
    res.status(500).send("Server error");
  }
});

// Start the server
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
