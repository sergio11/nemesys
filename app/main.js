import React from 'react';
import {Router,browserHistory} from 'react-router';
import ReactDOM from 'react-dom';
import Rosetta from '@schibstedspain/rosetta';
import Polyglot from '@schibstedspain/rosetta/lib/adapters/polyglot';
import languages from './languages';
/*
React Router bootstraps the routes from routes.js file,
matches them against a URL, and then executes the appropriate callback handler
*/
import routes from './routes';

const i18n = new Rosetta({adapter: new Polyglot()});
i18n.languages = languages;
i18n.culture = 'es';
const RouterI18n = i18n.addToContext(Router);

/*
We use history to enable HTML5 History API and to programmatically transition between routes.
Routes are now passed in to the <Router> component as children instead of prop
*/
ReactDOM.render(<RouterI18n history={browserHistory}>{routes}</RouterI18n>, document.getElementById('app'));