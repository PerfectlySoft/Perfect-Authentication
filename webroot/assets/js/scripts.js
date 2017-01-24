/*!
* A.mphibio.us  1.5.2
* Copyright 2014, @cliveMoore @Treefrog
* http://a.mphibio.us
* Free to use under the MIT license.
* http://www.opensource.org/licenses/mit-license.php
* 21/11/2014
*
*/

/* ==================================================================
 * amp object is the foundation namespaced A.mphibio.us JS
 * Do not remove or comment out.
 * ================================================================== */
var amp = {};

/* ==================================================================
 * amp.init is run on DOM ready
 * Do not remove or comment out.
 * ================================================================== */
amp.init = function() {
	/* ==================================================================
		* cache: uncomment if you wish to enable and add content caching only.
		* ================================================================== */
	// amp.cache();

	/* ==================================================================
		* amp.bindlisteners() is an essential function. Do not remove or comment out.
		* ================================================================== */
	amp.bindlisteners();

	/* ==================================================================
		* Discern mobile or desktop and init specific behaviour for each.
		* ================================================================== */
	if (!Modernizr.touch) {
		amp.desktoplisteners();
	} else {
		amp.mobilelisteners();
	}

};

amp.cache = function() {
	/* ==================================================================
		* Add content caching here
		* ================================================================== */
	amp.dom = {};
};

amp.bindlisteners = function() {
	/* ==================================================================
		* Bind Listeners
		* These are bound once the scripts, css and DOM are fully loaded
		* ================================================================== */

	/* General layout helpers */
	$('table td:first-child').addClass('first');
	$('table tr:nth-child(2n+1)').addClass('odd');
	$('table tr:nth-child(2n)').addClass('even');
	$('table tr:first-child').addClass('first');
	$('table tr:last-child').addClass('last');
	$('table td:first-child').addClass('first');
	$('table td:last-child').addClass('last');
	$('table th:first-child').addClass('first');
	$('table th:last-child').addClass('last');
	$('ul li:first-child').addClass('first');
	$('ul li:last-child').addClass('last');


	$(document).on('click', '.checkall', (function () {
		$(this).closest('fieldset').find(':checkbox').prop('checked', this.checked);
	}));

	$(document).on('click', '#nav li', (function(){
		if ($(this).hasClass('active')) {
		} else {
			$('#nav li').removeClass('active');
			$(this).addClass('active');
			/* I May use this later
			$(content).show().addClass('active').siblings().hide().removeClass('active'); */
		}
	}));

	$(document).on( 'click', '.tabs li a', (function(){
		var parent = $(this).closest('ul').attr('id');
		var content = '#'+$(this).attr('amp-tab-content');
		if ($(this).hasClass('active') && content.length) {
		} else {
			if (parent > 0)
			{
				$('#'+parent+'.tabs li a').removeClass('active');
				$(this).addClass('active');
			} else {
				$('.tabs li a').removeClass('active');
				$(this).addClass('active');
			}
			$(content).show().addClass('active').siblings().hide().removeClass('active');
		}
		return false;
	}));

	$(document).on('change', '.options_select', (function(){
		
		var target = '.options_div.' + $(this).val();
		
		$('.options_div').each(function(){
			$(this).addClass('hide');
		});
		console.log(target);
		if( $(target).length > 0 ){
			$(target).removeClass('hide');
		}
	}));


	$(document).on( 'click', '.opener', (function(){
		
		var thisOfCourse = $(this).attr('amp-target');
		
		if($('#'+$(this).attr('amp-target')).hasClass('hide')){
			$('#'+thisOfCourse+'').removeClass('hide');
		} else {
			$('#'+thisOfCourse+'').addClass('hide');
		}
	}));
	
	$(document).on( 'click', '.amp_trigger', (function(){
		
		var myLocal = $(this).attr('location');
		
		if($(this).attr('clicktype') == 'out') {
			window.open($(this).attr('location'));
		} else {
			document.location.href = $(this).attr('location');
		}
	}));

	$(document).on( 'click', '.modal_opener', (function(){
		
		var thisOfCourse = $(this).attr('amp-target');
		
		if($('#'+$(this).attr('amp-target')).hasClass('show')){
			$('body').css('overflow','auto');
			$('#'+thisOfCourse+'').removeClass('show');
			$('.focus').removeClass('blur');
		} else {
			$('body').css('overflow','hidden');
			$('#'+thisOfCourse+'').addClass('show').css('overflow','auto');
			$('.focus').addClass('blur');

			var content = '#'+$(this).attr('amp-tab-content');
			var contenttabheader = '#trigger_'+$(this).attr('amp-tab-content');
			
			if ($(contenttabheader).hasClass('active') && content.length) {
			} else {
				$('.tabs li a').removeClass('active');
				$(contenttabheader).addClass('active');
				$(content).show().addClass('active').siblings().hide().removeClass('active');
			}

		}
	}));

	$(document).on( 'click', '.modal_kill', (function(){
		var killIt = $(this).attr('amp-target');
			$('body').css('overflow','auto');
			$('#'+killIt+'').removeClass('show');
			$('.focus').removeClass('blur');
	}));
	
	$(document).on( 'click', '#searchtoggle, .search_cancel', (function(){
		if($('#searchtoggle').hasClass('active')){
			$('#searchtoggle').removeClass('active');
			$('#search_form').removeClass('open');
		} else {
			$('#searchtoggle').addClass('active');
			$('#search_form').addClass('open');
		}
	}));
	

	$(document).on( 'click', '#navtoggle', (function(){
		
		if($('#navtoggle').hasClass('active')){
			$('#navtoggle').removeClass('active');
			$('#mobilenav').removeClass('open');
		} else {
			$('#navtoggle').addClass('active');
			$('#mobilenav').addClass('open');
		}
	}));
};

amp.mobilelisteners = function() {
	/* ==================================================================
		* Mobile browser specific listeners are placed here
		* *** NOT *** executed by desktop browsers. See amp.desktoplisteners instead.
		* ================================================================== */

		//define dragging, set to false by default
		var dragging = false
		
		//set dragging active
		$("body").on("touchmove", function(){
			dragging = true;
		});
		
		//reset dragging
		$("body").on("touchstart", function(){
			dragging = false;
		});
	
		$(document).on('click', '#mobilenav ul.mainnav li a', (function(event){
			
			console.log('click');
	
			// prevent immediate link following on non iOS and BB devices
			var iOS = (navigator.userAgent.match(/iPad|iPhone|iPod/g) ? true : false);
			var BB = (navigator.userAgent.match(/Blackberry|BB/g) ? true : false);
	
			if(iOS == false || BB == false) {
	
				var siblings = $(this).siblings('ul, .drop').length;
	
				if($(this).hasClass('activated') || siblings < 1 ) {
					//go ahead, follow link
				} else {
					event.preventDefault();
					$(this).addClass('activated');
				}
				
			}
	
		}));
	
		$(document).on('touchend', '#mobilenav ul.mainnav li a', function(){
			
			console.log('touchend');
	
			if(dragging = false) {
	
				var siblings = $(this).siblings('ul').length;
			
				if(siblings > 1) {
					$(this).addClass('okgo');
				}
	
			}
	
		});
	
		$(document).on('click', '#mobilenav li.okgo > a', function(){
			window.location.href($(this).attr('href'));
		});

};

amp.desktoplisteners = function() {
	/* ==================================================================
		* Desktop browser specific listeners are placed here
		* *** NOT *** executed by mobile browsers. See amp.mobilelisteners instead.
		* ================================================================== */
	$(document).on('click', '.makereq', function(){
		amp.makeRequest($(this).attr('data'),$(this).attr('loc'));
		return false
	});
	$(document).on('click', '.deleteaction', function(){
	   var r = confirm("Are you sure you wish to delete this item?");
	   if (r == true) {
				   var dest = $(this).attr('dest');
				   $.ajax({
						  method: 'DELETE',
						  url: $(this).attr('href'),
						  data: {}
						  })
				   .done(function() {
						 location.href = dest;
						 });
	   }
	   
		return false
	});

};

$(document).ready(function() {
	/* ==================================================================
		* The document.ready is executed once all scripts and CSS are loaded
		* and the DOM has been readied.
		* Generally is used to bind listeners for responsive web
		* Generally a good thing to add listeners to the object,
		* however it is ok to be putting listeners directly in here.
		* ================================================================== */
	amp.init(); // don't delete this - it is part of the A.mphibio.us startup

});

amp.makeRequest = function(req, dest) {
	$.ajax({
		   method: 'POST',
		   url: req,
		   data: {}
		   })
	.done(function() {
		location.href = dest;
	});

}

amp.openCreate = function(t) {
	$('#listDiv').hide();
	$('#typeToggle').text('Create')
	$('#createName').val('')
	$('#appuuid').val('')
	$('#modDiv').show();
}



amp.openList = function() {
	$('#listDiv').show();
	$('#modDiv').hide();
}



amp.loadLog = function(filter, sessionid) {
	$.ajax({
		beforeSend: function(request) {
			request.setRequestHeader("Authorization", "Bearer "+sessionid);
		},
		method: 'POST',
		url: "/api/v1/get/log/",
		data: JSON.stringify(filter)
	})
	.done(function(data) {
		var body = [];
		console.log(data)
		for(i = 0; i < data.results.length; i++) {
			var o = "<td class=\""+data.results[i].loglevel+"\">["+data.results[i].loglevel+"]</td>"
			o += "<td>"+data.results[i].dategenerated+"</td>"
			o += "<td><a href=\"#\" class=\"eventid\" data=\""+data.results[i].eventid+"\">"+data.results[i].eventid+"</a></td>"
			o += "<td><a href=\"#\" class=\"appid\" data=\""+data.results[i].appuuid+"\">"+data.results[i].appName+"</a></td>"
			// Detail display
			o += "<td class=\"detaildisplay\">"
// 			o += "<div class=\"nodisplay\"> > Display</div>"
			
// 			o += "<div class=\"dodisplay\" style=\"display:none\">"
			o += "<div class=\"dodisplay\">"
			
			
			Object.keys(data.results[i].detail).forEach(function (prop) {  
				o += '<div class="row rb">'
				o += '<div class="col four first filterprop" data="' + prop + '"><span class="icon-search"></span> ' + prop + '</div>'
				o += '<div class="col twelve last propdata">' + data.results[i].detail[prop] + '</div>'
				o += '</div>'
			});			
			o += "</div>"

			o += "</td>"

			body[body.length] = o
		}
		$('#logview').html('<tr>' + body.join('</tr><tr>') + '</tr>')
		$('.eventid').on('click', function(event){
			event.preventDefault();
			filter.eventid = $(this).attr('data');
			amp.loadLog(filter,sessionid);
		});
		$('.appid').on('click', function(event){
			event.preventDefault();
			filter.appid = $(this).attr('data');
			amp.loadLog(filter,sessionid);
		});
		$('.nodisplay').on('click', function(event){
			event.preventDefault();
			$(this).hide();
			$(this).siblings('.dodisplay').show();
		});
		
		$('.filterprop').on('click', function(){
			filter.prop = $(this).attr('data');
			filter.propdata = encodeURI($(this).siblings('.propdata').text());
			amp.loadLog(filter,sessionid);
		});

	});
	
}
