import React from 'react';
import {Route,IndexRoute} from 'react-router';
import App from './components/App/App';
import Login from './components/Login/Login';
import Logout from './components/Logout/Logout';
import SignUp from './components/SignUp/SignUp';
import ChangePassword from './components/ChangePassword/ChangePassword';
import Home from './components/Home/Home';
import Conversations from './components/Conversations/Conversations'
import Firebase from './firebase';

const AppRouter = (props, context) => {
  context.i18n.culture = 'en';
  return (<App {...props} />);
}

AppRouter.contextTypes = {
    i18n: React.PropTypes.object
};


function requireAuth(nextState, replace) {
    let authData = Firebase.getAuth();
    if (!authData) {
        replace({
            pathname: '/login',
            state: { nextPathname: nextState.location.pathname }
        })
    }
}


export default (
  <Route path='/' component={AppRouter}>
    <IndexRoute  component={Home} onEnter={requireAuth}/>
    <Route path='login' component={Login} />
    <Route path='signup' component={SignUp} />
    <Route path='logout' component={Logout} />
    <Route path='change-password' component={rChangePassword}  />
    <Route path='home'  component={Home} onEnter={requireAuth}/>
  </Route> 
);