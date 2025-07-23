# Product Customizer API

This is a simple Express + MongoDB backend to save customized product JSON data from your frontend (e.g., using Fabric.js) to a MongoDB database.

## Features
- POST endpoint to save product customization data
- Flexible schema (accepts any JSON structure)
- CORS enabled for frontend integration

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start MongoDB:**
   - Make sure MongoDB is running locally on `mongodb://localhost:27017` (default port).

3. **Run the server:**
   ```bash
   npm run dev   # for development (auto-restart)
   # or
   npm start     # for production
   ```

## API Usage

### Save Product Customization
- **Endpoint:** `POST /api/save-product`
- **Content-Type:** `application/json`
- **Body:** (your product customization JSON)

#### Example (Frontend)
```js
fetch('http://localhost:5000/api/save-product', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(yourProductData)
})
  .then(res => res.json())
  .then(data => console.log(data));
```

## Notes
- The schema is flexible; you can make it strict by editing `server.js`.
- Make sure MongoDB is running before starting the server. 