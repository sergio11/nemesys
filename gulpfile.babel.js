'use strict';
import gulp from 'gulp'
import gulpLoadPlugins from 'gulp-load-plugins';
import source from 'vinyl-source-stream';
import babelify from 'babelify';
import browserify from 'browserify';
import watchify from 'watchify';
const plugins = gulpLoadPlugins({
  rename:{
    'gulp-util': 'util',
    'gulp-if': 'if',
    'gulp-streamify': 'streamify',
    'gulp-autoprefixer': 'autoprefixer',
    'gulp-cssmin': 'cssmin',
    'gulp-sass': 'sass',
    'gulp-concat': 'concat',
    'gulp-plumber': 'plumber',
    'gulp-uglify': 'uglify',
    'gulp-sourcemaps': 'sourcemaps',
    'gulp-size': 'size',
    'gulp-notify': 'notify',
    'gulp-react-templates': 'rt'
  },
  scope: 'devDependencies'
});

const production = process.env.NODE_ENV === 'production';
const dependencies = [
  'react',
  'react-dom',
  'react-bootstrap',
  'react-router',
  'react-router-bootstrap',
  'velocity-react'
];

/*
 |--------------------------------------------------------------------------
 | Combine all JS libraries into a single file for fewer HTTP requests.
 |--------------------------------------------------------------------------
 */
gulp.task('vendor', () => {
  return gulp.src([
    'bower_components/jquery/dist/jquery.js',
  ]).pipe(plugins.concat('vendor.js'))
    .pipe(plugins.if(production, plugins.uglify({ mangle: false })))
    .pipe(gulp.dest('public/js'))
    .pipe(plugins.size({
      title: "Vendor Libraries"
    }))
});

/*
 |--------------------------------------------------------------------------
 | Compile third-party dependencies separately for faster performance.
 |--------------------------------------------------------------------------
 */
gulp.task('browserify-vendor', () => {
  return browserify()
    .ignore('cls-bluebird')
    .require(dependencies)
    .bundle()
    .pipe(source('vendor.bundle.js'))
    .pipe(plugins.if(production, plugins.streamify(plugins.uglify({ mangle: false }))))
    .pipe(gulp.dest('public/js'))
    .pipe(plugins.size({
      title: "Vendor Bundle"
    }))
    .pipe(plugins.notify("Vendor Bundle done!"));
});


/*
 |--------------------------------------------------------------------------
 | Copile React Templates
 |--------------------------------------------------------------------------
 */

gulp.task('rt', function() {
    return gulp.src('app/components/**/*.rt')
        .pipe(plugins.rt({modules: 'es6'}))
        .pipe(gulp.dest('app/components'))
        .pipe(plugins.size({
            title: "React Templates"
        }))
});


/*
 |--------------------------------------------------------------------------
 | Compile only project files, excluding all third-party dependencies.
 |--------------------------------------------------------------------------
 */
gulp.task('browserify', ['browserify-vendor','rt'], () => {
  return browserify({ entries: 'app/main.js', debug: true })
    .external(dependencies)
    .transform(babelify, { presets: ['es2015', 'react'] })
    .bundle()
    .pipe(source('bundle.js'))
    .pipe(plugins.streamify(plugins.sourcemaps.init({ loadMaps: true })))
    .pipe(plugins.if(production, plugins.streamify(plugins.uglify({ mangle: false }))))
    .pipe(plugins.streamify(plugins.sourcemaps.write('.')))
    .pipe(gulp.dest('public/js'))
    .pipe(plugins.size({
      title: "App Bundle"
    }))
});

/*
 |--------------------------------------------------------------------------
 | Same as browserify task, but will also watch for changes and re-compile.
 |--------------------------------------------------------------------------
 */
gulp.task('browserify-watch', ['browserify-vendor','rt'], () => {
  let bundler = watchify(browserify({ entries: 'app/main.js', debug: true }, watchify.args));
  bundler.external(dependencies);
  bundler.transform(babelify, { presets: ['es2015', 'react'] })
  bundler.on('update', rebundle);
  return rebundle();

  function rebundle() {
    let start = Date.now();
    return bundler.bundle()
      .on('error', (err) => {
        plugins.util.log(plugins.util.colors.red(err.toString()));
      })
      .on('end', () => {
        plugins.util.log(plugins.util.colors.green('Finished rebundling in', (Date.now() - start) + 'ms.'));
      })
      .pipe(source('bundle.js'))
      .pipe(plugins.streamify(plugins.sourcemaps.init({ loadMaps: true })))
      .pipe(plugins.streamify(plugins.sourcemaps.write('.')))
      .pipe(gulp.dest('public/js/'))
      .pipe(plugins.size({
        title: "App Bundle"
      }))
      .pipe(plugins.notify("App Bundle done!"));
  }
});


/*
 |--------------------------------------------------------------------------
 | Copy vendor assets
 |--------------------------------------------------------------------------
 */
gulp.task('copy', () => {

  return gulp.src([
    'node_modules/**/dist/fonts/*',
    'node_modules/**/dist/*.css',
  ])
  .pipe(gulp.dest('public/vendor/'))
  .pipe(plugins.size({
    title: 'vendor assets'
  }))

});


/*
 |--------------------------------------------------------------------------
 | Copy web fonts to dist
 |--------------------------------------------------------------------------
*/

gulp.task('fonts', () => {
  return gulp.src('bower_components/bootstrap-sass-official/assets/fonts/**')
    .pipe(gulp.dest('public/fonts/'))
    .pipe(plugins.size({
      title:"Fonts"
    }))
});



/*
 |--------------------------------------------------------------------------
 | Compile sass stylesheets.
 |--------------------------------------------------------------------------
 */
gulp.task('styles', () => {
  return gulp.src('app/stylesheets/main.sass')
    .pipe(plugins.plumber({errorHandler: plugins.notify.onError("Error in styles task: <%= error.message %>")}))
    .pipe(plugins.sass())
    .pipe(plugins.autoprefixer())
    .pipe(plugins.if(production, plugins.cssmin()))
    .pipe(gulp.dest('public/css'))
    .pipe(plugins.size({
      title:"Styles"
    }))
});

gulp.task('watch', () => {
  gulp.watch('app/stylesheets/**/*.sass', ['styles']);
});


gulp.task('default', ['styles','fonts','copy','vendor', 'browserify-watch', 'watch']);
gulp.task('build', ['styles', 'fonts','copy','vendor', 'browserify']);