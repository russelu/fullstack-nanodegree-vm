Hi, welcome to my Splatoon2 Fanclub on AWS ubuntu.

IP address:
52.10.115.114 PORT 2200

URL:
splatoon2fc.com

Software Installed:
Python, PostgreSQL, Git, apache2, mod_wsgi
(within Python: psycopg2, flask, flask_sqlalchemy, virtualenv)

Configurations:
A. SSH is limited on port 2200
    1 sudo ufw deny 22
    2 sudo ufw allow 2200
    3 sudo nano /etc/ssh/sshd_config
	Change Port from 22 to 2200
    4 sudo service ssh restart
B. create su grader
    1 sudo adduser grader
    2 add grader to /etc/sudoers.d/
C. only allow remote connection on ports 2200(ssh), 80(http), 123(ntp)
    1 sudo ufw allow 2200 
    2 sudo ufw allow www
    3 sudo ufw allow 123
    4 sudo ufw enable
D. Apache2 & mod_wsgi setup and set DaemonProcess to Python virtual environment
    1 sudo apt-get install apache2
    2 sudo apt-get install libapache2-mod-wsgi
    3 sudo nano /etc/apache2/sites-available/000-default.conf 
	Change root document path, python-path to venv
    4 modify myapp.wsgi, to point to python main app.
E. Set up Python environment and add same libraries to venv using Virtualenv
    flask, sqlalchemy, requests, passlib, itsdangerous
F. key-based SSH authentication is enforced
    1 ssh-keygen
    2 add public key to /home/grader/.ssh/authorized_keys
G. git repo:
    /workspace/catalog_app/
H. SSH key for grader is stored at
    /home/grader/.ssh/authorized_keys


--------------------------------------------
--------Copied from Previous project--------
--------------------------------------------
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
--Notice: name cannot contain '/'
--login required

/catalog/new_item
--add new item to database
--Notice: name cannot be empty, or ended w/ '.json'. category cannot be empty.
--Notice: name cannot contain '/'
--login required

/catalog/<category_name>/<item_name>
--show item info
--if category and item don't match, you will be redirected to home page
--if logged in, you can edit and delete this item

/catalog/<category_name>/edit
--edit this category
--Notice: name cannot be empty, or ended w/ '.json'
--Notice: name cannot contain '/'
--login required

/catalog/<category_name>/delete
--delete this category
--login required

/catalog/<category_name>/<item_name>/edit
--edit this item
--if category and item don't match, you will be redirected to home page
--Notice: name cannot be empty, or ended w/ '.json'. category cannot be empty.
--Notice: name cannot contain '/'
--login required

/catalog/<category_name>/<item_name>/delete
--delete this item
--if category and item don't match, you will be redirected to home page
--login required

/catalog.json
/catalog/<category_name>.json
/catalog/<category_name>/<item_name>.json
--JSON endpoint
