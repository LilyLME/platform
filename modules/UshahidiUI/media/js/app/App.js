define(['jquery', 'backbone', 'marionette', 'underscore', 'handlebars', 'App.oauth'],
	function($, Backbone, Marionette, _, Handlebars, OAuth) {
		var App = new Backbone.Marionette.Application();
		
		// Save oauth object in App - just in case
		App.oauth = OAuth;
		
		//Organize Application into regions corresponding to DOM elements
		//Regions can contain views, Layouts, or subregions nested as necessary
		App.addRegions(
		{
			body : "body"
		});
	
		function isMobile() {
			var ua = (navigator.userAgent || navigator.vendor || window.opera, window, window.document);
			return (/iPhone|iPod|iPad|Android|BlackBerry|Opera Mini|IEMobile/).test(ua);
		}
	
		App.mobile = isMobile();
	
		App.addInitializer(function(options) {
			Backbone.history.start();
		});
		
		// Global config params
		// @todo dynamically get this from kohana
		var site = {
			'baseurl' : '',
			'imagedir' : 'media/kohana/images'
		};
		
		Handlebars.registerHelper('baseurl', function() {
			return site.baseurl;
		});
		
		Handlebars.registerHelper('url', function(url) {
			return site.baseurl + '/' + url;
		});
		
		Handlebars.registerHelper('imageurl', function(url) {
			return site.baseurl + '/' + site.imagedir +  '/' + url;
		});
	
		return App;
	}); 