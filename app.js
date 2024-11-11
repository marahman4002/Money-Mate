const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const PDFDocument = require("pdfkit");

const User = require("./models/User"); // Assumes User model is in models/User.js

const app = express();
const PORT = process.env.PORT || 3000;
const conn = process.env.DB_URI || "mongodb://localhost:27017/Money-Mate"
const SECRET_KEY = process.env.SECRET_KEY || "your_jwt_secret_key"; // Replace with a secure key in production

// Connect to MongoDB
mongoose
  .connect(conn)
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("Failed to connect to MongoDB", error);
    process.exit(1); // Exit app if DB connection fails
  });

// Middleware for parsing form data and cookies
app.use(express.urlencoded({ extended: true, limit: "3mb" }));
app.use(cookieParser({ limit: "3mb" }));

// Middleware to make auth status available in all views
function authMiddleware(req, res, next) {
  const token = req.cookies.jwt;
  if (token) {
    try {
      // Verify the token and extract user data
      const decoded = jwt.verify(token, SECRET_KEY);
      res.locals.isAuthenticated = true;
      res.locals.user = { name: decoded.name, email: decoded.email }; // Store name and email only
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        // Handle expired token error
        // res.status(401).json({ message: "Session expired. Please log in again." });
        res.redirect("/signin");
      } else {
        // Handle any other JWT error
        // res.status(401).json({ message: "Invalid session. Please log in again." });
        // res.locals.isAuthenticated = false;
        // res.locals.user = null; // In case of invalid or expired token
        res.redirect("/signin");
      }
      res.locals.isAuthenticated = false;
      res.locals.user = null; // In case of invalid or expired token
      res.redirect("/signin");
    }
  } else {
    res.locals.isAuthenticated = false;
    res.locals.user = null; // No token found
    // res.status(401).json({ message: "No session found. Please log in." });
    res.redirect("/signin");
  }
  next();
}

// Set EJS as the template engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, "public")));

// Public routes that don't require authentication
app.get("/signin", (req, res) => {
  if (res.locals.isAuthenticated) {
    console.log("Already Signed In Redirecting to / from sign in");
    res.redirect("/");
  }
  res.render("signin");
});

app.get("/signup", (req, res) => {
  if (res.locals.isAuthenticated) {
    console.log("Already Signed In Redirecting to / from sign up");
    res.redirect("/");
  }
  res.render("signup");
});

// Sign-up Route
app.post("/signup", async (req, res) => {
  const { name, number, email, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.status(400).json({ message: "Passwords do not match" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const newUser = new User({ name, number, email, password });
    await newUser.save();

    const token = jwt.sign(
      { id: newUser._id, name: newUser.name, email: newUser.email },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.cookie("jwt", token, { httpOnly: true });
    res.status(200).json({ message: "Account created successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error during sign-up" });
  }
});

// Sign-in Route
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email }).select("email password name");
    if (!user || !(await bcrypt.compare(password, user.password))) {
      console.log("User not found");
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.cookie("jwt", token, { httpOnly: true });
    res.status(200).json({ message: "Logged in successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error during sign-in" });
  }
});

// Authenticated routes that require the user to be logged in
app.use(authMiddleware);

app.get("/", authMiddleware, async (req, res) => {
  try {
    const email = res.locals.user.email; // Assuming you are storing the user ID in req.user (after JWT verification)
    // Fetch the current month's transactions for the logged-in user
    const user = await User.findOne({ email }).select(
      "cur_month_credit cur_month_debit cur_month_balance cur_month_trans tot_trans"
    );

    // Render the view with the data
    res.render("index", {
      tt: user.tot_trans,
      cur_month_trans: user.cur_month_trans.slice(-5).reverse(),
      cur_month_credit: user.cur_month_credit,
      cur_month_debit: user.cur_month_debit,
      cur_month_balance: user.cur_month_balance,
    });
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).send("Server error");
  }
});

app.get("/history", authMiddleware, async (req, res) => {
  try {
    const email = res.locals.user.email; // Assuming you are storing the user ID in req.user (after JWT verification)
    // Fetch the Total transactions for the logged-in user
    const user = await User.findOne({ email }).select(
      "total_credit total_debit total_balance tot_trans"
    );

    // Render the view with the data
    res.render("history", {
      user: req.user,
      tot_trans: user.tot_trans.slice(-5).reverse(),
      total_credit: user.total_credit,
      total_debit: user.total_debit,
      total_balance: user.total_balance,
    });
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).send("Server error");
  }
});

app.get("/generate-pdf", authMiddleware, async (req, res) => {
  try {
    // Fetch users and their transactions
    const email = res.locals.user.email; // Assuming you are storing the user ID in req.user (after JWT verification)
    // Fetch the Total transactions for the logged-in user
    const user = await User.findOne({ email }).select(
      "name email number tot_trans"
    );

    // Create a new PDF document
    const doc = new PDFDocument();

    // Set the response to be a downloadable PDF
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${user.name}_transactions.pdf"`
    );

    // Pipe the PDF to the response
    doc.pipe(res);

    // Add a title
    doc.fontSize(16).text("User Transactions", { align: "center" });
    doc.moveDown(2);

    // Loop through each user and their transactions
    doc
      .fontSize(14)
      .text(`${user.name}   (${user.email})   +91 (${user.number})`, {
        underline: true,
        align: true,
      });
    doc.moveDown(1);

    doc
      .fontSize(14)
      .text(
        `Date Time                           From/To:       Description:       Type:      Amount:`
      );
    // Get transactions for the current user
    const userTransactions = user.tot_trans;

    if (userTransactions.length > 0) {
      userTransactions.forEach((transaction) => {
        doc.moveDown(1);
        // doc
        //   .fontSize(12)
        //   .text(`Date: ${transaction.date_time.toLocaleDateString()}`);
        //   doc.text(`From/To: $${transaction.frmto}`);
        //   doc.text(`Description: ${transaction.note}`);
        //   doc.text(`Type: $${transaction.type}`);
        // doc.text(`Amount: $${transaction.amount}`);
        doc.fontSize(12).text(
          `${transaction.date_time.toLocaleString("en-US", {
            weekday: "short",
            year: "numeric",
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          })}   ${transaction.frmto}             ${
            transaction.note
          }                   ${transaction.type}            ${
            transaction.amount
          }`
        );

        // If there's a photoId, replace it with a "Proof" hyperlink
        if (transaction.photoId) {
          doc
            .text(`Proof: `, { continued: true })
            .underline(doc.x, doc.y, 50, 0) // Creates the underline (useful for clickable text)
            .text("Click here", {
              link: `http://localhost:3000/proof/${transaction._id.toString()}`,
            });
        }
      });
    } else {
      doc.fontSize(12).text("No transactions found for this user.");
      doc.moveDown(1);
    }

    doc.moveDown(2); // Add some space between users

    // Finalize the PDF file
    doc.end();
  } catch (err) {
    console.error(err);
    res.status(500).send("Error generating PDF");
  }
});

// Route to handle adding a new transaction
app.post("/add-transaction", authMiddleware, async (req, res) => {
  const { type, amount, frmto, note, proof } = req.body; // `proof` will be Base64 string
  try {
    const email = res.locals.user.email; // Assuming user ID is stored in JWT token for current user
    const date_time = new Date(); // Capture the transaction timestamp

    // Fetch the current user from the database
    const user = await User.findOne({ email });

    // Prepare the transaction entry
    const newTransaction = {
      date_time,
      type,
      frmto,
      amount: parseFloat(amount),
      note,
      photoId: proof, // Store the Base64 encoded image in the transaction
    };

    // Add to current month transactions and total transactions
    user.cur_month_trans.push(newTransaction);
    newTransaction["_id"] =
      user.cur_month_trans[user.cur_month_trans.length - 1];
    user.tot_trans.push(newTransaction);

    // Update current month and total credit/debit based on transaction type
    if (type === "credit") {
      user.cur_month_credit += newTransaction.amount;
      user.total_credit += newTransaction.amount;
      user.cur_month_balance += newTransaction.amount;
      user.total_balance += newTransaction.amount;
    } else if (type === "debit") {
      user.cur_month_debit += newTransaction.amount;
      user.total_debit += newTransaction.amount;
      user.cur_month_balance -= newTransaction.amount;
      user.total_balance -= newTransaction.amount;
    }

    // Save the updated user information
    await user.save();

    res.status(200).json({ message: "Transaction added successfully!" });
  } catch (error) {
    console.error("Error adding transaction:", error);
    res
      .status(500)
      .json({ message: "Failed to add transaction. Please try again." });
  }
});

app.post('/del/:tid',authMiddleware ,async (req, res) => {
  const { tid } = req.params;

  try {
    // Find the user (you can customize this part to find by _id, email, etc.)
    const email = res.locals.user.email;
    const user = await User.findOne({email});  // Example: Replace with dynamic user identifier (e.g., user._id or req.user._id)
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Find transaction in current month transactions (cur_month_trans)
    const curMonthIndex = user.cur_month_trans.findIndex((trans) => trans._id.toString() === tid);
    // Find transaction in total transactions (tot_trans)
    const totTransIndex = user.tot_trans.findIndex((trans) => trans._id.toString() === tid);

    // If transaction is not found in both arrays
    if (curMonthIndex === -1 && totTransIndex === -1) {
      return res.status(404).json({ error: "Transaction not found." });
    }

    // Remove the transaction from cur_month_trans and tot_trans
    if (curMonthIndex !== -1) {
      user.cur_month_trans.splice(curMonthIndex, 1);
    }

    if (totTransIndex !== -1) {
      user.tot_trans.splice(totTransIndex, 1);
    }

    // Recalculate the balances
    await recalculateBalances(user);

    // Save the updated user document
    await user.save();

    return res.status(200).json({
      message: "Transaction deleted successfully.",
      user,
    });
    
  } catch (err) {
    console.error("Error during transaction deletion: ", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// Helper function to recalculate user balances
const recalculateBalances = async (user) => {
  let newTotalCredit = 0, newTotalDebit = 0, newTotalBalance = 0;
  let newMonthCredit = 0, newMonthDebit = 0, newMonthBalance = 0;

  // Recalculate total transactions (ignore deleted ones)
  user.tot_trans.forEach((trans) => {
    if (!trans.deleted) {
      if (trans.type === 'credit') newTotalCredit += trans.amount;
      if (trans.type === 'debit') newTotalDebit += trans.amount;
    }
  });

  // Recalculate current month transactions (ignore deleted ones)
  user.cur_month_trans.forEach((trans) => {
    if (!trans.deleted) {
      if (trans.type === 'credit') newMonthCredit += trans.amount;
      if (trans.type === 'debit') newMonthDebit += trans.amount;
    }
  });

  // Calculate the new balances
  newTotalBalance = newTotalCredit - newTotalDebit;
  newMonthBalance = newMonthCredit - newMonthDebit;

  // Update user totals
  user.total_credit = newTotalCredit;
  user.total_debit = newTotalDebit;
  user.total_balance = newTotalBalance;

  // Update current month totals
  user.cur_month_credit = newMonthCredit;
  user.cur_month_debit = newMonthDebit;
  user.cur_month_balance = newMonthBalance;
};

// Route to serve the transaction proof image
app.get("/proof/:tid", authMiddleware, async (req, res) => {
  try {
    const transactionId = req.params.tid;

    const email = res.locals.user.email; // Assuming you are storing the user ID in req.user (after JWT verification)

    const user = await User.findOne({ email }).select("cur_month_trans");

    if (!user) {
      return res.status(404).json({ message: "Transaction not found" });
    }

    // Get the transaction
    const transaction = user.cur_month_trans.find(
      (t) => t._id.toString() === transactionId
    );

    if (!transaction || !transaction.photoId) {
      return res.status(404).json({ message: "Proof not found" });
    }

    // Send the Base64 encoded image (ensure it's the correct MIME type)
    res.set("Content-Type", "image/jpeg");
    res.send(Buffer.from(transaction.photoId, "base64"));
  } catch (error) {
    console.error("Error fetching proof:", error);
    // res.status(500).json({ message: "Server error" });
    red.redirect("/signin");
  }
});

// Logout Route
app.get("/logout", (req, res) => {
  res.clearCookie("jwt");
  console.log("Signed OUT i.e. LOGOUT Redirecting to /signin");
  // res.status(200).json({ message: "Logged out successfully" });
  res.status(200).redirect("signin");
});

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: "Internal server error" });
});

app.get("/*" || "/*/*", (req, res) => {
  res.send("<h1>4$4 Brother</h1>");
});

// Start the server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
