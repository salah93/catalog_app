# todo

## prettify
+ split into modules?
+ add css
+ comments
+ tests
+ add github oauth

# done
+ edit json to inlcude item_id
+ docstrings
+ go through guidelines
+ find way to retrieve right items when viewing/editing/deleting (TODO)
    + add item id to item_page, edit_item, delete_item
+ setup database
+ layout routes
+ make sure each get/post skeletons are set up
+ for route in routes:
    + implement route
    + test route
+ implement logout
+ profile
+ add/edit/favorite
+ add more json endpoints
+ flash messages
+ make images round
+ 404 page
+ add generate csrftoken again
    + send csrf token to all views that post
+ ajax return data as string so form.get does not work
+ other form return data as form.get
+ find a way to check for both for state token

# log
#### 2016-11-29 19:18:20.090064
setup routes v 1
#### 2016-12-05 20:46:39.708024
set up routes v 2
#### 2016-12-05 22:18:04.572010
setup database, add decorators to check for log in and csrf protection
#### 2016-12-06 17:07:44.601855
implement routes
#### 2016-12-06 17:08:33.828055
implement logout
#### 2016-12-07 19:48:12.568142
add icons to add/edit/fave, add all templates, complete most of backend
