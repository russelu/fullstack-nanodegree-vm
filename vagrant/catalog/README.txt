Hi, welcome to my catalog app.

Build steps:
1 vagrant up; vagrant ssh;
2 cd catalog
3 python views.py

You will have both Google and Facebook authendication in this app

Homepage:
localhost:5000

------- All Pages ------
/
/catalog
--show all products and items
--if logged in, you can add new category and item

/catalog/<category_name>
--show category items
--if logged in, you can edit and delete this category. also, you can add new item.(it doesn't have to be under this category)

/catalog/new_category
--add new category to database
--Notice: name cannot be empty, or ended w/ '.json'
--login required

/catalog/new_item
--add new item to database
--Notice: name cannot be empty, or ended w/ '.json'. category cannot be empty.
--login required

/catalog/<category_name>/<item_name>
--show item info
--if category and item don't match, you will be redirected to home page
--if logged in, you can edit and delete this item

/catalog/<category_name>/edit
--edit this category
--login required

/catalog/<category_name>/delete
--delete this category
--login required

/catalog/<category_name>/<item_name>/edit
--edit this item
--if category and item don't match, you will be redirected to home page
--login required

/catalog/<category_name>/<item_name>/delete
--delete this item
--if category and item don't match, you will be redirected to home page
--login required

/catalog.json
/catalog/<category_name>.json
/catalog/<category_name>/<item_name>.json
--JSON endpoint