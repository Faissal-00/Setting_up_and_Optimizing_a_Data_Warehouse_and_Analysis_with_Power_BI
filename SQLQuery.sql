create database StagingAreaEcommerce
create database WareahouseEcommerce
use StagingAreaEcommerce
select * from StAEcommerce
select * from transformed_data
use WareahouseEcommerce

select * from CustomerDimension
select * from SupplierDimension
select * from ShipperDimension
select * from ProductDimension
select * from DateDimension

select * from SalesFact
select * from InventoryFact


create database SalesDataMart
create database InventoryDataMart