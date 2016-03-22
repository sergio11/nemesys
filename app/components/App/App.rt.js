import React from 'react/addons';
import _ from 'lodash';
import Navbar from '../Navbar/Navbar';
import { RouteTransition } from 'react-router-transition';
export default function () {
    return React.createElement('div', {}, React.createElement(Navbar, {}), React.createElement(RouteTransition, {
        'component': 'main',
        'pathname': this.props.location.pathname,
        'atEnter': {
            translateX: -100,
            opacity: 0.7
        },
        'atLeave': {
            translateX: 100,
            opacity: 0
        },
        'atActive': {
            translateX: 0,
            opacity: 1
        },
        'mapStyles': styles => ({
            opacity: styles.opacity,
            transform: `translateX(${ styles.translateX }%)`
        })
    }, '\r\n        ', this.props.children, '\r\n    '));
};