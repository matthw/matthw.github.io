var css = ['blue.css', 'brown.css', 'default.css', 'green.css', 'red.css', 'yellow.css'];

$(document).ready(function() {
    var style = css[Math.floor(Math.random() * css.length)];

    $('head').append('<link rel="stylesheet" href="css/' + style + '" type="text/css" />');
});
