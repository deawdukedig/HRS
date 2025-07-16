# HRS (Hardware Repair Service)

A simple Node.js app to manage hardware repair service jobs, collect customer/device info, technician notes, and print work receipts with auto-incrementing job numbers.

## Features

- Collect customer name, phone number, device name, symptom, and technician notes.
- Auto-numbered work tickets with SQLite data storage.
- Printable job receipt (two A5 receipts on A4: shop & customer copy).
- Overlay editable fields on a custom receipt background.
- Minimal dependencies (Express, EJS, SQLite3).
- List all jobs for admin review.

## Quick Start

1. **Install dependencies:**

   ```bash
   npm install
   ```

2. **Add your receipt background:**  
   Place your receipt background image as `public/receipt-bg.jpg`.

3. **Start the server:**

   ```bash
   npm start
   ```

4. **Open your browser:**  
   Visit [http://localhost:3000](http://localhost:3000).

## Printing

On the receipt page, use the **Print Receipt (A4)** button.  
Prints two A5 receipts side by side (left: shop, right: customer) on A4 paper.

## Database

- Jobs are stored in `hrs.db` (SQLite).
- To add `technicianNotes` to an existing database, run:
  ```sql
  ALTER TABLE jobs ADD COLUMN technicianNotes TEXT;
  ```

## License

MIT