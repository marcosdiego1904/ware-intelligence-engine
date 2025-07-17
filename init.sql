USE test_ware_engine;

CREATE TABLE inventory_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    location_code VARCHAR(255) NOT NULL,
    pallet_id VARCHAR(255),
    item_sku VARCHAR(255),
    item_description TEXT,
    quantity INT,
    expiry_date DATE,
    creation_date DATETIME,
    receipt_number VARCHAR(255)
);

INSERT INTO inventory_data (location_code, pallet_id, item_sku, item_description, quantity, expiry_date, creation_date, receipt_number) VALUES
('A1-01-01', 'PALLET001', 'SKU12345', 'Canned Beans', 100, '2025-12-31', NOW() - INTERVAL 2 DAY, 'LOT001'),
('A1-01-02', 'PALLET002', 'SKU12346', 'Canned Corn', 150, '2025-11-30', NOW() - INTERVAL 5 DAY, 'LOT001'),
('B2-04-05', 'PALLET003', 'SKU12347', 'Tomato Sauce', 200, '2024-10-15', NOW() - INTERVAL 10 DAY, 'LOT002'),
('RECEIVING', 'PALLET004', 'SKU12348', 'Olive Oil', 120, '2026-01-01', NOW() - INTERVAL 10 HOUR, 'LOT003'); 