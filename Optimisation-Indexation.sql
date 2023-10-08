use WareahouseEcommerce

-- Create non-clustered indexes on columns
CREATE NONCLUSTERED INDEX IX_Date ON DateDimension (Date);
CREATE NONCLUSTERED INDEX IX_ProductName ON ProductDimension (ProductName);
CREATE NONCLUSTERED INDEX IX_ProductSubCategorie ON ProductDimension (ProductSubCategory);
CREATE NONCLUSTERED INDEX IX_ProductCategorie ON ProductDimension (ProductCategory);
CREATE NONCLUSTERED INDEX IX_SupplierName ON SupplierDimension (SupplierName);
CREATE NONCLUSTERED INDEX IX_SupplierLocation ON SupplierDimension (SupplierLocation);