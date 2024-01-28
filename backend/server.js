import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const PORT = 4000;
const mongoURL = "mongodb://localhost:27017";
const dbName = "quirknotes";

// Connect to MongoDB
let db;

async function connectToMongo() {
  const client = new MongoClient(mongoURL);

  try {
    await client.connect();
    console.log("Connected to MongoDB");

    db = client.db(dbName);
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
}

connectToMongo();
// Open Port
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });

// Collections to manage
const COLLECTIONS = {
    notes: "notes",
    users: "users",
  };

// Register a new user
app.post("/registerUser", express.json(), async (req, res) => {
    try {
      const { username, password } = req.body;
  
      // Basic body request check
      if (!username || !password) {
        return res
          .status(400)
          .json({ error: "Username and password both needed to register." });
      }
  
      // Checking if username does not already exist in database
      const userCollection = db.collection(COLLECTIONS.users);
      const existingUser = await userCollection.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: "Username already exists." });
      }
  
      // Creating hashed password (search up bcrypt online for more info)
      // and storing user info in database
      const hashedPassword = await bcrypt.hash(password, 10);
      await userCollection.insertOne({
        username,
        password: hashedPassword,
      });
  
      // Returning JSON Web Token (search JWT for more explanation)
      const token = jwt.sign({ username }, "secret-key", { expiresIn: "1h" });
      res.status(201).json({ response: "User registered successfully.", token });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Log in an existing user
app.post("/loginUser", express.json(), async (req, res) => {
    try {
      const { username, password } = req.body;
  
      // Basic body request check
      if (!username || !password) {
        return res
          .status(400)
          .json({ error: "Username and password both needed to login." });
      }
  
      // Find username in database
      const userCollection = db.collection(COLLECTIONS.users);
      const user = await userCollection.findOne({ username });
  
      // Validate user against hashed password in database
      if (user && (await bcrypt.compare(password, user.password))) {
        const token = jwt.sign({ username }, "secret-key", { expiresIn: "1h" });
  
        // Send JSON Web Token to valid user
        res.json({ response: "User logged in succesfully.", token: token }); //Implicitly status 200
      } else {
        res.status(401).json({ error: "Authentication failed." });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Post a note belonging to the user
app.post("/postNote", express.json(), async (req, res) => {
    try {
      // Basic body request check
      const { title, content } = req.body;
      if (!title || !content) {
        return res
          .status(400)
          .json({ error: "Title and content are both required." });
      }
  
      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
        if (err) {
          return res.status(401).send("Unauthorized.");
        }
  
        // Send note to database
        const collection = db.collection(COLLECTIONS.notes);
        const result = await collection.insertOne({
          title,
          content,
          username: decoded.username,
        });
        res.json({
          response: "Note added succesfully.",
          insertedId: result.insertedId,
        });
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Retrieve a note belonging to the user
app.get("/getNote/:noteId", express.json(), async (req, res) => {
    try {
      // Basic param checking
      const noteId = req.params.noteId;
      if (!ObjectId.isValid(noteId)) {
        return res.status(400).json({ error: "Invalid note ID." });
      }
  
      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
        if (err) {
          return res.status(401).send("Unauthorized.");
        }
  
        // Find note with given ID
        const collection = db.collection(COLLECTIONS.notes);
        const data = await collection.findOne({
          username: decoded.username,
          _id: new ObjectId(noteId),
        });
        if (!data) {
          return res
            .status(404)
            .json({ error: "Unable to find note with given ID." });
        }
        res.json({ response: data });
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Retrieve all notes belonging to the user
app.get("/getAllNotes", express.json(), async (req, res) => {
  try {
      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
          if (err) {
              return res.status(401).json({ error: "Unauthorized." });
          }

          // Find all notes belonging to the authenticated user
          const collection = db.collection(COLLECTIONS.notes);
          const notes = await collection.find({ username: decoded.username }).toArray();
          
          if (!notes || notes.length === 0) {
              // It's okay to return an empty array if no notes are found
              return res.status(200).json({ response: [] });
          }

          // Constructing the response array
          const response = notes.map(note => {
              return {
                  _id: note._id,
                  title: note.title,
                  content: note.content,
                  username: note.username
              };
          });

          // Sending the response
          res.status(200).json({ response: response });
      });
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});

app.delete("/deleteNote/:noteId", express.json(), async (req, res) => {
  try {
      const noteId = req.params.noteId;

      // Check if the noteId is valid
      if (!ObjectId.isValid(noteId)) {
          return res.status(400).json({ error: "Invalid note ID." });
      }

      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
          if (err) {
              return res.status(401).json({ error: "Unauthorized." });
          }

          // Fetch the note to ensure it belongs to the user
          const collection = db.collection(COLLECTIONS.notes);
          const note = await collection.findOne({
              _id: new ObjectId(noteId),
              username: decoded.username,
          });

          // Check if the note exists and belongs to the user
          if (!note) {
              return res.status(404).json({ error: "Note not found or does not belong to the user." });
          }

          // Delete the note
          await collection.deleteOne({ _id: new ObjectId(noteId) });

          // Sending the response
          res.status(200).json({ response: `Document with ID ${noteId} properly deleted.` });
      });
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});

app.patch("/editNote/:noteId", express.json(), async (req, res) => {
  try {
      const noteId = req.params.noteId;
      const { title, content } = req.body;

      // Check if the noteId is valid
      if (!ObjectId.isValid(noteId)) {
          return res.status(400).json({ error: "Invalid note ID." });
      }

      // Check if the request body is valid (at least one field should be provided)
      if (!title && !content) {
          return res.status(400).json({ error: "At least one of title or content must be provided." });
      }

      // Construct update object based on provided fields
      let updateFields = {};
      if (title) updateFields.title = title;
      if (content) updateFields.content = content;

      // Verify the JWT from the request headers
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, "secret-key", async (err, decoded) => {
          if (err) {
              return res.status(401).json({ error: "Unauthorized." });
          }

          // Fetch the note to ensure it belongs to the user
          const collection = db.collection(COLLECTIONS.notes);
          const note = await collection.findOne({
              _id: new ObjectId(noteId),
              username: decoded.username,
          });

          // Check if the note exists and belongs to the user
          if (!note) {
              return res.status(404).json({ error: "Note not found or does not belong to the user." });
          }

          // Update the note
          await collection.updateOne({ _id: new ObjectId(noteId) }, { $set: updateFields });

          // Sending the response
          res.status(200).json({ response: `Document with ID ${noteId} properly updated.` });
      });
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});

