import React from 'react';
import {Route,IndexRoute} from 'react-router';
import App from './components/App/App';
import Login from './components/Login/Login';
import Logout from './components/Logout/Logout';
import SignUp from './components/SignUp/SignUp';
import Home from './components/Home/Home';
import Conversations from './components/Conversations/Conversations'

const AppRouter = (props, context) => {
  context.i18n.culture = 'en';
  return (<App {...props} />);
}

AppRouter.contextTypes = {
    i18n: React.PropTypes.object
};


export default (
  <Route path='/' component={AppRouter}>
    <IndexRoute  component={Login} />
    <Route path='login' component={Login} />
    <Route path='signup' component={SignUp} />
    <Route path='logout' component={Logout} />
    <Route path='home'  component={Home} />
  </Route> 
);