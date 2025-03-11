const express = require('express');

// bcrypt hashing of password 
const bcrypt = require('bcrypt');


// comcept of jwt token is being once customer and vendor login and register 


const jwt = require('jsonwebtoken');

const { v4: uuidv4 } = require('uuid');  // unique code 16 digit for product id and usr id reference - https://www.uuidgenerator.net/

const AWS = require('aws-sdk');
const fetch = require('node-fetch');
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');

const multer = require('multer');
const multerS3 = require('multer-s3'); // compatible with  aws sdk v2 for linux ec2 instance 



require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// comment - cross origin resource sharing for interaction with react
app.use(cors());

AWS.config.update({region: process.env.AWS_REGION,
});

// document db calling ------

const dynamodb = new AWS.DynamoDB.DocumentClient();
// s3 client calling 
const s3 = new AWS.S3();


const ses = new AWS.SES({ apiVersion: '2010-12-01' });

// Nodemailer setting up for email mailing using node service 

const transportertest = nodemailer.createTransport({service: 'gmail',auth: { user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,},
});

const sendNodemailerOTP = (email, otp) => {
  const mailOptions = {from: process.env.EMAIL_USERNAME,to: email,subject: 'Your OTP Code', text: `Your OTP code is: ${otp}`,};

  return transportertest.sendMail(mailOptions);
};
// ses implementation for vendor type has been taking place




// testing code in ses 
const sesotpsend = (email, otp) => {const params = {
	
	
    Source: process.env.SES_EMAIL, Destination: { ToAddresses: [email] },Message: {
		
      Subject: { Data: 'Your OTP Code' }, Body: { Text: { Data: `Your OTP code is: ${otp}` } 
	  },
    },
  };

  return ses.sendEmail(params).promise();
};

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString(); // 6 digits

// validating the email 


const emailvalidation = (email) => {
  const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return regex.test(email);
};

// password validation min 8 charactrs taken


const validatePassword = (password) => {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_\-])[A-Za-z\d@$!%*?&_\-]{8,}$/;
  return regex.test(password);
};

const queryUser = async (field, value) => {
  const params = {
    TableName: 'Users',   // Users is the dynamo db table in the backend 
    FilterExpression: `${field} = :value`,
    ExpressionAttributeValues: { ':value': value },
  };
  return dynamodb.scan(params).promise();
};

// token verification of the closed routes has been taking place in the app
const verifyToken = (req, res, next) => {
	
	
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ errorCode: 'ERR_NO_TOKEN', message: 'No token provided.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(500).json({ errorCode: 'ERR_INVALID_TOKEN', message: 'Failed to authenticate token.' });
	
    req.userId = decoded.id; // state jwt user id for fetching 
	
    next();
  });
};

// Helping  function to transform DynamoDB response format for json
const transformDynamoDBResponse = (items) => {
  return items.map((item) => {
    return {id: item.id.S,
      name: item.name.S,
      category: item.category.S,
      price: item.price.N,
      description: item.description.S,
      stock_quantity: item.stock_quantity.N,
      created_at: item.created_at.S,
      updated_at: item.updated_at.S,
      supplier: item.supplier.S,
      image_url: item.image_url.S,
    };
  });
};

// Store OTP in DynamoDB with expiration time
const storeOTPInDB = async (email, otp) => {
  const expirationTime = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutes from now time limit of expire 
  
  const params = {
	  
	  // created date is the current date and expiration time is the time taken after 15 mins  
	  
    TableName: 'UserOTPs',
    Item: {
      email,
      otp,
      createdAt: new Date().toISOString(),
      expiresAt: expirationTime,
    },
  };
  
  return dynamodb.put(params).promise();
};

// Retrieve OTP from DynamoDB
const retrieveOTPFromDB = async (email) => {
	
  const params = {
	  
    TableName: 'UserOTPs',
	
    Key: {
      email,
    },
  };
  return dynamodb.get(params).promise();
};

// Delete OTP from DynamoDB after verification
const deleteOTPFromDB = async (email) => {
  const params = {
    TableName: 'UserOTPs',
    Key: {
      email,
    },
  };
  return dynamodb.delete(params).promise();
};

// registering the  user by verifying the username or  email and by default customer is used 

app.post('/register', async (req, res) => {  // sending the post method for registering 
	// below code is given to handle 
	
  const { username, email, password, user_type = 'customer' } = req.body;

  if (!username || !email || !password) 
  {
    return res.status(400).json({ errorCode: 'ERR_MISSING_FIELDS', message: 'Username, email and password are required.' });
  }

  if (!emailvalidation(email)) return res.status(422).json({ errorCode: 'ERR_INVALID_EMAIL', message: 'Invalid email format exists.' });
  if (!validatePassword(password)) return res.status(423).json({ errorCode: 'ERR_WEAK_PASSWORD', message: 'Password does not meet the requirements.' });

  try {
	  // now checking the errors like if user exists or not 
    const emailData11 = await queryUser('email', email);
    if (emailData11.Items.length > 0) 
	{
      return res.status(409).json({ errorCode: 'ERR_EMAIL_EXISTS', message: 'Email already exists so, please choose the another.' });
    }

    const usernameData1 = await queryUser('username', username);
	
    if (usernameData1.Items.length > 0) 
	{
      return res.status(410).json({ errorCode: 'ERR_USERNAME_EXISTS', message: 'username already exists. Please choose another.' });
    }
  } catch (error) {
    return res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error checking username and email uniqueness.' });
  }

  const id = uuidv4(); // uuid generation for uniqueness
  
  const hashedPassword = await bcrypt.hash(password, 10); 
  // pass word hashing for securing accesss 
  
  const createdAt = new Date().toISOString(); // tyep conversion

  const params = {
    TableName: 'Users',
    Item: {
      id,
      username,
      email,
      password_hash: hashedPassword,
      created_at: createdAt,
      user_type,
      verified: false, // 'verified' to false initially
    },
  };

  try {
    await dynamodb.put(params).promise();

    // Send OTP and store it in DynamoDB
    const otp = generateOTP();
    await storeOTPInDB(email, otp);

    if (user_type === 'customer') {
      await sendNodemailerOTP(email, otp);
    } else if (user_type === 'vendor') {
      await sesotpsend(email, otp);
    }
    res.status(201).json({ message: 'User registered successfully. Please verify OTP sent to your email.' });
  } catch (error) {
	  // loging the error is must as I got stuck in this 
    //console.log({ error });
	
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error registering the  user.' });
  }
});

// verifying  OTP for Registration/Login for both the user type for customer and vendor type 
app.post('/verify-otp', async (req, res) => {
	
	// email otp is taken 
  const { email, otp } = req.body;

  try {
	  // otp taken from the database 
	  
    const result = await retrieveOTPFromDB(email);
	  // console.log(result) comment has beeen made to check object 
    if (!result.Item) 
	{
	
      return res.status(400).json({ errorCode: 'ERR_INVALID_OTP', message: 'Invalid OTP. Please try it again.' });
    }

    const { expiresAt } = result.Item; // fetching the expire at column from ot to check if the otp expire or not 
    if (new Date() > new Date(expiresAt)) 
	{
      await deleteOTPFromDB(email);
	  // waiting to function to execute in order to retrieve the otp and deleting the same 
	  
      return res.status(400).json({ errorCode: 'ERR_EXPIRED_OTP', message: 'OTP expired. Please request a new one.' });
    }

    //console.log('Stored OTP:', String(result.Item.otp).trim());
	
	// this thing was not working for me so check otp - 
	
    //console.log('Provided OTP:', String(otp).trim());

    if (String(result.Item.otp).trim() !== String(otp).trim()) {  // trim the string to remove the otp unneccesary spaces 
      // console.log('Stored OTP:', String(result.Item.otp).trim());
      // console.log('Provided OTP:', String(otp).trim());
      return res.status(400).json({ errorCode: 'ERR_INVALID_OTP', message: 'Invalid OTP. Please try again' });
    }

    // deleting the  OTP from DynamoDB after verification 
    await deleteOTPFromDB(email);

    // updatingd  the user's verified status if user type is customer
    const userData = await queryUser('email', email);
    if (userData.Items.length > 0) 
	{
      const user = userData.Items[0];
	  
	  
      const userId = user.id; // Extracting  the user's id as the key of Users table
      
      if (user.user_type === 'customer') {
        const updateParams = {TableName: 'Users',
          Key: { id: userId },
          UpdateExpression: 'set verified = :verified',
          ExpressionAttributeValues: {
            ':verified': true,
          },
        };

        await dynamodb.update(updateParams).promise();

        // fetching the user data after update to get the correct verified status done successfully as it will turn to yes or true  post verification case is handling
		
        const updatedUserData = await queryUser('email', email);
        const isVerified = updatedUserData.Items[0].verified ? true : false; // using the verified field from updated user data

        if (isVerified) 
		{ // verifying the otp, sending the token --------------------------------------------------
	
          const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRATION_TIME });
          return res.json({
            verify: 1, // Sending 1 if verified
            message: 'OTP verified successfully.',
            token
          });
        } else {
          return res.json({
			  // using verify check for the frontend to show the error if it is not verifies as 200 styatus code will go so implemented the flag 
            verify: 0, // Sending 0 if not verified
            message: 'OTP verified successfully but User is not verified.'
          });
        }
      }

      if (user.user_type === 'vendor') {
        // Check if the vendor is verified
        const isVerified = user.verified ? true : false; // Using the verified field from user data
        if (isVerified) {
          const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRATION_TIME });
          res.json({
            verify: 1, // Sending 1 if verified
            message: 'OTP verified successfully.',
            token
          });
        } else {
          res.json({
            verify: 0, // Sending 0 if not verified
            message: 'OTP verified successfully. Request to admin has been sent. We will communicate the result post reviewing your form.'
          });
        }
      }
    }
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error verifying OTP.' });
  }
});

//  User logging part case handled -----
app.post('/login', async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ errorCode: 'ERR_MISSING_CREDENTIALS', message: 'Username or email and password are required.' });
  }

  try {
    // Verify user by identifier (email or username) using ternary operator as both are unique like github profile  
	
    const data = await queryUser(emailvalidation(identifier) ? 'email' : 'username', identifier);
    if (!data.Items.length) {
      return res.status(404).json({ errorCode: 'ERR_USER_NOT_FOUND', message: 'User not found.' });
    }

    const user = data.Items[0];

    // Verifying  the password to check if everything is matching or not !!
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) 
	{
		
      return res.status(401).json({ errorCode: 'ERR_INVALID_PASSWORD', message: 'Incorrect password' });
    }

    // Check if the user is verified
	
	// ternary operator is applying 
    const isVerified = user.verified ? true : false; 
    
    // will throw error if the user is not verified done 
    if (!isVerified && user.user_type === 'vendor') 
	{
      return res.status(403).json({ errorCode: 'ERR_NOT_VERIFIED', message: 'user is not verified. Please contact admin for more details.' });
    }

    // sending the OTP and store it in DynamoDB
    const otp = generateOTP();
    await storeOTPInDB(user.email, otp); // email is primary key in that as otp we r storing 
    
    if (user.user_type === 'customer') {
      await sendNodemailerOTP(user.email, otp);
    } else if (user.user_type === 'vendor') {
      await sesotpsend(user.email, otp);
    }

    res.status(201).json({ message: 'Please verify OTP sent to your email to login.' });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error logging in.' });
  }
});


// Logout user the case ----
app.post('/logout', (req, res) => {
  res.json({ message: 'Logout successful' });
});

// open route case is used to  View all products as in ecom user can see without login in cart it will redirected to login page 

app.get('/products', async (req, res) => {
	// api gateway and lambda concept has been used for scalability and fast searching is used ------------------------
  const apiUrl = `${process.env.API_GATEWAY_URL}/products`; // api gateway implement using lambda function in aws
  try {
    const response = await fetch(apiUrl);
    if (!response.ok) {
      throw new Error('Error fetching products from the API');
    }
    const products = await response.json();
    const transformedProducts = transformDynamoDBResponse(products);
    res.json(transformedProducts);
    // console.log('transformed products is :', transformedProducts);
  } catch (error) {
    console.error('Error fetching products:', error.message);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error fetching products.' });
  }
});

// open route searching product also implemented using api gateway using lambda call 
app.get('/products/search', async (req, res) => {
	
	
  const { searchString } = req.query;

  if (!searchString) 
  {
    return res.status(400).json({ errorCode: 'ERR_INVALID_QUERY', message: 'search string is required.' });
  }
// comment taking from .env file gateway ------------------------------------
  const apiUrl = `${process.env.API_GATEWAY_URL}/products/search?searchString=${encodeURIComponent(searchString)}`;
  try {
    const response = await fetch(apiUrl);
    if (!response.ok) 
	{ 
     //  throwing the error -------
      throw new Error('Error fetching products');
    }

    const products = await response.json();
    res.json(products);
  } catch (error) {
    console.error('Error fetching products from the API is ', error);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error fetching products from the API' });
  }
});

// comment  - view product by ID where it is being sent as path parameter and the concept is being used for get method

app.get('/products/:id', async (req, res) => {
	
  const apiUrl = `${process.env.API_GATEWAY_URL}/products/${req.params.id}`;
  try {
    const response = await fetch(apiUrl);
    if (!response.ok) {
      throw new Error('Error fetching product');
    }
    const product = await response.json();
    const transformedProduct = transformDynamoDBResponse([product])[0]; // transform single productand sending in json format 
    res.json(transformedProduct);
  } catch (error) {
    console.error('Error fetching product from the API.', error);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'error fetching product from the API.' });
  }
});


// adding the  Item to Cart concept is being handle in below code 
app.post('/cart/add', verifyToken, async (req, res) => {
  const { product_id, quantity } = req.body;
  const user_id = req.userId;

  if (!product_id || !quantity) {
    return res.status(400).json({ errorCode: 'ERR_MISSING_FIELDS', message: 'Product ID and quantity are required.' });
  }

  try {
    const productUrl = `${process.env.API_GATEWAY_URL}/products/${product_id}`;
    const productResponse = await fetch(productUrl, {
      headers: { Authorization: req.headers['authorization'] }  // jwt token in header -----
    });

    if (!productResponse.ok) {
      throw new Error('Error fetching product information');
    }

    const product = await productResponse.json();
    
    if (parseInt(product.stock_quantity, 10) < quantity) {   // typecasting --- checking added product quantity is greater tha available throw error 
      return res.status(400).json({ errorCode: 'ERR_INSUFFICIENT_STOCK', message: 'Insufficient stock available.' });
    }

    const params = {
      TableName: 'carts',  // backend carts table 
      Item: {
        user_id,
        product_id,
        added_at: new Date().toISOString(),
        quantity: quantity.toString(),
      }
    };

    await dynamodb.put(params).promise();
    res.status(201).json({ message: 'Item added to cart successfully.' });
  } catch (error) {
    //console.log({error});
    
    // console.error('Error adding item to cart:', error.message);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error adding item to cart.' });
  }
});
// deleting the cart case is being handle in below cases ------- based on user id and product id 
app.delete('/cart/delete', verifyToken, async (req, res) => {
  const { product_id, quantity } = req.body;
  const user_id = req.userId;

  if (!product_id || !quantity) {
    return res.status(400).json({ errorCode: 'ERR_MISSING_FIELDS', message: 'Product ID and quantity are required.' });
  }

  try {
    const getParams = {
      TableName: 'carts',
      Key: {
        user_id,
        product_id,
      },
    };

    const cartItem = await dynamodb.get(getParams).promise();

    if (!cartItem.Item) {
      return res.status(404).json({ errorCode: 'ERR_ITEM_NOT_FOUND', message: 'Item is not found in the cart.' });
    }

    const currentQuantity = parseInt(cartItem.Item.quantity, 10);

    if (quantity >= currentQuantity) 
	{
      await dynamodb.delete(getParams).promise();
      res.status(200).json({ message: 'Item is removed from cart successfully.' });
    } else {
      const newQuantity = currentQuantity - quantity;
      const updateParams = {
        TableName: 'carts',
        Key: {user_id,
          product_id,},
		  
        UpdateExpression: 'set quantity = :newQuantity',
        ExpressionAttributeValues: {
          ':newQuantity': newQuantity.toString(),
        },
        ReturnValues: 'UPDATED_NEW',
      };

      await dynamodb.update(updateParams).promise();
      res.status(200).json({ message: 'Item quantity updated successfully.' });
    }
  } catch (error) {
    console.error('Error updating item quantity in cart:', error.message);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error updating item quantity in cart.' });
  }
});

// getting the Items from cart based on the user id 
app.get('/cart', verifyToken, async (req, res) => {
  const user_id = req.userId;

  const params = {
    TableName: 'carts',
    KeyConditionExpression: 'user_id = :user_id',
    ExpressionAttributeValues: {
		
      ':user_id': user_id,
    },
  };

  try {
    const result = await dynamodb.query(params).promise();
    res.status(200).json(result.Items);
  } catch (error) {
    console.error('Error fetching items from cart:', error.message);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error fetching items from cart' });
  }
});

// vendor dashboards curls started  from the below ------



// multer functionality is used to upload the image in s3 bucket in this cases with env file keeping the bucket name as nuku and unique file is created using uuid generator appended by date 
const upload = multer({
  storage: multerS3({
    s3: s3, // Use the S3 client created with AWS SDK v2 - comment 
    bucket: process.env.S3_BUCKET_NAME,
    key: (req, file, cb) => {
      const fileName = `${uuidv4()}_${Date.now()}_${file.originalname}`;
      cb(null, fileName);
    },
    contentType: multerS3.AUTO_CONTENT_TYPE,
  }),
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 MB limit set initially so that we can't initilaize more than that as budget of 5 dollar is being set with size set is being used 
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) { // handling image type data ------
      return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
  },
});


// routing  to add a new product with image upload in db for vendor dashboard post verifying the jwt ----
app.post('/vendor/additem', verifyToken, upload.single('image'), async (req, res) => {
  const { category, description, name, price, stock_quantity } = req.body; 
  // URL of the uploaded image in S3
  const imageUrl = req.file ? req.file.location : null; // ternary operator to handle location -----
  const userId = req.userId; // Get userId from token

  // Validate required fields must be required
  if (!userId || !category || !description || !name || !price || !stock_quantity) {
    return res.status(400).json({ errorCode: 'ERR_MISSING_FIELDS', message: 'All fields are required.' });
  }

  try {
    // added new product with name_lowercase field for string matching. this is handle in the backend in lamda but user dont have to send lower case ---
    const params = {
      TableName: 'Products',
      Item: {
        id: uuidv4(),
        category,
        created_at: new Date().toISOString(),
        description,
        image_url: imageUrl,
        name,
        name_lowercase: name.toLowerCase(), 
        price: parseFloat(price),
        stock_quantity: parseInt(stock_quantity, 10),
        supplier: userId, // using userId from JWT token
        updated_at: new Date().toISOString()
      },
    };

    await dynamodb.put(params).promise();
    res.status(201).json({ message: 'Product added successfully.' });
  } catch (error) {
    console.error('Error adding item:', error);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error adding item.' });
  }
});

// implement 
// Route to fetch products by vendor ID with closed route and token verification so that he can verify the same. this is closed route 
app.get('/vendor/fetchitems', verifyToken, async (req, res) => {
  const userId = req.userId; // Extract userId from the token after verification

  try {
    // Fetch products by userId from jwt
    const params = {TableName: 'Products',
      FilterExpression: 'supplier = :supplier',
      ExpressionAttributeValues: {
        ':supplier': userId,
      },
    };

    const productsData = await dynamodb.scan(params).promise(); // getting data 
    res.status(200).json(productsData.Items);
  } catch (error) {
    console.error('Error fetching items:', error);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error fetching items.' });
  }
});


// Configure multer to upload files to S3 not using  acl is not 


// Route to update a product - closed route with token verification
app.put('/vendor/updateitem', verifyToken, async (req, res) => {
  const { productId, updateData } = req.body; // extracting productId and other update data from the request
  const userId = req.userId; // extract userId from the token state ---

  try {
    // this is the dynamic handling where user can send atleast one and parameter can increase
    let updateExpression = 'set';
    let expressionAttributeNames = {};
    let expressionAttributeValues = {};

    // dynamically construct the update expression based on provided fields in dynamodb
    if (updateData.category) {
      updateExpression += ' #category = :category,';
      expressionAttributeNames['#category'] = 'category';
      expressionAttributeValues[':category'] = updateData.category;
    }

    if (updateData.description) {
      updateExpression += ' #description = :description,';
      expressionAttributeNames['#description'] = 'description';
      expressionAttributeValues[':description'] = updateData.description;
    }

    if (updateData.price) {
      updateExpression += ' #price = :price,';
      expressionAttributeNames['#price'] = 'price';
      expressionAttributeValues[':price'] = updateData.price;
    }

    if (updateData.stock_quantity) {
      updateExpression += ' #stock_quantity = :stock_quantity,';
      expressionAttributeNames['#stock_quantity'] = 'stock_quantity';
      expressionAttributeValues[':stock_quantity'] = updateData.stock_quantity;
    }

    // remove last trailing comma from the update expression
    updateExpression = updateExpression.slice(0, -1); //slicing is happening 

    // ensure the supplier is matched for conditional update with user id ----
    expressionAttributeValues[':supplier'] = userId;

    // Check if at least one field is provided to update with db
    if (Object.keys(expressionAttributeValues).length === 1) 
      { // Only :supplier exists code 
      return res.status(400).json({ errorCode: 'ERR_NO_FIELDS_TO_UPDATE', message: 'No fields provided to update.' });
    }

    // Update the product with the specified id
    const params = {
      TableName: 'Products',
      Key: { id: productId },
      UpdateExpression: updateExpression,
      ExpressionAttributeNames: expressionAttributeNames,
      ExpressionAttributeValues: expressionAttributeValues,
      ConditionExpression: 'supplier = :supplier',
      ReturnValues: 'UPDATED_NEW', // for updating the product information ----
    };

    // Executing the update operation in dynamo db
    const updateResult = await dynamodb.update(params).promise();
    res.status(200).json({ message: 'Product updated successfully.', updatedAttributes: updateResult.Attributes });
  } catch (error) {
    console.error('Error updating item:', error);
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error updating item.' });
  }
});

// routing  to delete a product by product ID - closed route with token verification based on the product id 
app.delete('/vendor/deleteitem', verifyToken, async (req, res) => {
  const { productId } = req.query; // Extracting productId from the request query
  const userId = req.userId; // Get userId from the token

  try {
    // fetching  the product by productId and verify supplier id
    const productParams = {
      TableName: 'Products',
      Key: { id: productId },
    };

    const productData = await dynamodb.get(productParams).promise();

    if (!productData.Item) {
      return res.status(404).json({ errorCode: 'ERR_PRODUCT_NOT_FOUND', message: 'Product not found.' });
    }

    if (productData.Item.supplier !== userId) { // checking supplier id with user id ---
      return res.status(403).json({ errorCode: 'ERR_NOT_AUTHORIZED', message: 'you are not authorized to delete this product.' });
    }

    // delete the image from url ---- 
    const imageUrl = productData.Item.image_url;
    const imageKey = imageUrl.split('/').pop(); // Extract the file name from the URL s3

    const s3Params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: imageKey,
    };
   // deleting from s3 ---
   
   
    await s3.deleteObject(s3Params).promise();

    // delete the product from DynamoDB
    await dynamodb.delete(productParams).promise();

    res.status(200).json({ message: 'Product and associated image deleted successfully.' });
	
  } catch (error) 
  {
    console.error('Error deleting product:', error);
	
	
    res.status(500).json({ errorCode: 'ERR_SERVER_ERROR', message: 'Error deleting product.' });
  }
});

const PORT = process.env.PORT || 3000;  // 3000 is used as port listen for the url 
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});