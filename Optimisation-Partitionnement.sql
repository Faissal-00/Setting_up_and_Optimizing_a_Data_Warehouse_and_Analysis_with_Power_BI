use WareahouseEcommerce



CREATE PARTITION FUNCTION SalesDatePartitionFunction (DATE)
AS RANGE LEFT FOR VALUES ('2021-01-01', '2022-01-01', '2023-01-01');




ALTER DATABASE WareahouseEcommerce ADD FILEGROUP [FG_sales_Archive]
GO

ALTER DATABASE WareahouseEcommerce ADD FILEGROUP [FG_sales_2021]
GO

ALTER DATABASE WareahouseEcommerce ADD FILEGROUP [FG_sales_2022]
GO

ALTER DATABASE WareahouseEcommerce ADD FILEGROUP [FG_sales_2023]
GO

-----------------------------------

ALTER DATABASE WareahouseEcommerce ADD FILE
(NAME = N'Ventes_Archive',
FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\DATA\Ventes_Archive.ndf', SIZE = 2048KB) TO FILEGROUP [FG_sales_Archive];

ALTER DATABASE WareahouseEcommerce ADD FILE
(NAME = N'Ventes_2021',
FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\DATA\Ventes_2021.ndf', SIZE = 2048KB) TO FILEGROUP [FG_sales_2021];

ALTER DATABASE WareahouseEcommerce ADD FILE
(NAME = N'Ventes_2022',
FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\DATA\Ventes_2022.ndf', SIZE = 2048KB) TO FILEGROUP [FG_sales_2022];

ALTER DATABASE WareahouseEcommerce ADD FILE
(NAME = N'Ventes_2023',
FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\DATA\Ventes_2023.ndf', SIZE = 2048KB) TO FILEGROUP [FG_sales_2023];




CREATE PARTITION SCHEME SalesPartitionScheme
AS PARTITION SalesDatePartitionFunction
TO ([Primary], [FG_sales_2021], [FG_sales_2022], [FG_sales_2023]);

-----------------------------


CREATE VIEW SalesFactWithDateBase
AS
SELECT
    sf.SaleID,
    sf.DateID,
    sf.ProductID,
    sf.CustomerID,
    sf.ShipperID,
    sf.QuantitySold,
    sf.TotalAmount,
    sf.DiscountAmount,
	sf.NetAmount,
    dd.Date AS SalesDate
FROM
    SalesFact sf
JOIN
    DateDimension dd ON sf.DateID = dd.DateID;


----------------------------------------


-- Create a new partitioned fact table
CREATE TABLE SalesFactPartitioned
(
    SalesID INT,
    DateID INT,
    ProductID INT,
    CustomerID INT,
    ShipperID INT,
    QuantitySold INT,
    TotalAmount DECIMAL(10, 2),
    DiscountAmount DECIMAL(10, 2),
	NetAmount DECIMAL(10, 2),
    SalesDate DATE,
    PRIMARY KEY (SalesID, SalesDate)  -- Include SalesDate in the primary key
)
ON SalesPartitionScheme (SalesDate);



INSERT INTO SalesFactPartitioned (SalesID, DateID, ProductID, CustomerID, ShipperID, QuantitySold, NetAmount, TotalAmount, DiscountAmount, SalesDate)
SELECT SaleID, DateID, ProductID, CustomerID, ShipperID, QuantitySold, NetAmount, TotalAmount, DiscountAmount, SalesDate
FROM SalesFactWithDateBase;


SELECT 
	p.partition_number AS partition_number,
	f.name AS file_group, 
	p.rows AS row_count
FROM sys.partitions p
JOIN sys.destination_data_spaces dds ON p.partition_number = dds.destination_id
JOIN sys.filegroups f ON dds.data_space_id = f.data_space_id
WHERE OBJECT_NAME(OBJECT_ID) = 'SalesFactPartitioned'
order by partition_number;


----------------------------------------
-- Select data from the SalesFactPartitioned table
SELECT 
    SalesID,
    SalesDate,
    ProductID,
    CustomerID,
    QuantitySold,
    TotalAmount,
    DiscountAmount,
	NetAmount
FROM 
    SalesFactPartitioned
WHERE 
    SalesDate >= '2022-01-01' AND SalesDate < '2023-01-01';
------------------------------
-- Select aggregated data from the SalesFactPartitioned table
SELECT 
    dd.Year,
    pd.ProductCategory,
    SUM(sf.QuantitySold) AS TotalQuantitySold,
    SUM(sf.TotalAmount) AS TotalSalesAmount
FROM 
    SalesFactPartitioned sf
JOIN 
    DateDimension dd ON sf.DateID = dd.DateID
JOIN 
    ProductDimension pd ON sf.ProductID = pd.ProductID
WHERE 
    dd.Year IN (2022, 2023)
    AND pd.ProductCategory = 'Electronics'
GROUP BY 
    dd.Year, pd.ProductCategory;
