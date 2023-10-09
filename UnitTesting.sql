EXEC tSQLt.NewTestClass 'SalesFactTests';

CREATE PROCEDURE SalesFactTests.[test SaleID is unique]
AS
BEGIN
    -- Ensure that SaleID is unique
    EXEC tSQLt.AssertPrimaryKeyUnique 'dbo.SalesFact', 'SaleID';
END;


CREATE PROCEDURE SalesFactTests.[test ProductID references ProductDimension]
AS
BEGIN
    -- Ensure that ProductID in SalesFact references a valid ProductID in ProductDimension
    EXEC tSQLt.AssertForeignKeyRelationship 'dbo.SalesFact', 'ProductID', 'dbo.ProductDimension', 'ProductID';
END;


CREATE PROCEDURE SalesFactTests.[test No NULL values in QuantitySold]
AS
BEGIN
    -- Ensure that the QuantitySold column has no NULL values
    EXEC tSQLt.AssertIsNull 0, 'SELECT COUNT(*) FROM dbo.SalesFact WHERE QuantitySold IS NULL';
END;

EXEC tSQLt.Install;


EXEC tSQLt.Run 'SalesFactTests';


EXEC tSQLt.XmlResultFormatter;
