
JS_PATH=static/js
JS_FILES=$(wildcard $(JS_PATH)/*.js)

CSS_PATH=static/css
CSS_FILES=$(wildcard $(CSS_PATH)/*.css)

all: coffee sass

coffee: $(JS_FILES)
sass: $(CSS_FILES)

%.js: %.coffee
	coffee -c $<

%.css: %.scss
	sassc -I $(dir $<) $< >$@.new
	mv $@.new $@
