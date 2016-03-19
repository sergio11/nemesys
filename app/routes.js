import React from 'react';
import {Route,IndexRoute} from 'react-router';
import App from './components/App/App';
import Home from './components/Home/Home';

const AppRouter = (props, context) => {
  context.i18n.culture = 'en';
  return (<App {...props} />);
}

AppRouter.contextTypes = {
    i18n: React.PropTypes.object
};

export default (
  <Route path='/' component={AppRouter}>
    <IndexRoute  component={Home} />
  </Route> 
);