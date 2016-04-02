import React from 'react/addons';
import _ from 'lodash';
import Navbar from '../Navbar/Navbar';
import { RouteTransition } from 'react-router-transition';
export default function () {
    return React.createElement('div', {}, React.createElement(Navbar, { 'authData': this.state.auth_data }), React.createElement(RouteTransition, {
        'component': 'main',
        'pathname': this.props.location.pathname,
        'atEnter': { translateX: -100 },
        'atLeave': { translateX: 100 },
        'atActive': { translateX: 0 },
        'mapStyles': styles => ({ transform: `translateX(${ styles.translateX }%)` })
    }, '\r\n        ', React.cloneElement(this.props.children, { 'authData': this.state.auth_data }), '\r\n    '));
};