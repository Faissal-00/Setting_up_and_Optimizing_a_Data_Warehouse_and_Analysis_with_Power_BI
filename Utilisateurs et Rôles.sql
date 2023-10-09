-- Use the target database
USE WareahouseEcommerce;


-- Create server-level logins with passwords
CREATE LOGIN DataEngineerLogin WITH PASSWORD = 'DataEngineer2004';
CREATE LOGIN DataAnalystLogin WITH PASSWORD = 'DataAnalyst2004';


-- Create database users
CREATE USER DataEngineerUser FOR LOGIN DataEngineerLogin;
CREATE USER DataAnalystUser FOR LOGIN DataAnalystLogin;

-- Create database roles for Data Engineer and Data Analyst
CREATE ROLE DataEngineerRole;
CREATE ROLE DataAnalystRole;

-- Add users to their respective roles
ALTER ROLE DataEngineerRole ADD MEMBER DataEngineerUser;
ALTER ROLE DataAnalystRole ADD MEMBER DataAnalystUser;

-- Grant permissions to DataEngineerRole
GRANT SELECT ON SalesFact TO DataEngineerRole;
GRANT INSERT ON SalesFact TO DataEngineerRole;
GRANT UPDATE ON SalesFact TO DataEngineerRole;
GRANT DELETE ON SalesFact TO DataEngineerRole;

GRANT SELECT ON SupplierDimension TO DataEngineerRole;
GRANT SELECT ON ProductDimension TO DataEngineerRole;
GRANT SELECT ON ShipperDimension TO DataEngineerRole;
GRANT SELECT ON DateDimension TO DataEngineerRole;



-- Grant permissions to DataAnalystRole
GRANT SELECT ON SalesFact TO DataAnalystRole;
GRANT SELECT ON SupplierDimension TO DataAnalystRole;
GRANT SELECT ON ProductDimension TO DataAnalystRole;
GRANT SELECT ON ShipperDimension TO DataAnalystRole;
GRANT SELECT ON DateDimension TO DataAnalystRole;



