import React from 'react/addons';
import _ from 'lodash';
import Navbar from '../Navbar/Navbar';
import Grid from 'react-bootstrap/lib/Grid';
import Row from 'react-bootstrap/lib/Row';
import Col from 'react-bootstrap/lib/Col';
import { RouteTransition } from 'react-router-transition';
export default function () {
    return React.createElement('div', {}, React.createElement(Navbar, { 'authData': this.state.auth_data }), React.createElement(RouteTransition, {
        'component': 'main',
        'pathname': this.props.location.pathname,
        'atEnter': { translateX: -100 },
        'atLeave': { translateX: 100 },
        'atActive': { translateX: 0 },
        'mapStyles': styles => ({ transform: `translateX(${ styles.translateX }%)` })
    }, React.createElement('div', { 'className': 'signup-page' }, React.createElement('div', { 'className': 'wrapper' }, React.createElement('div', {
        'className': 'header header-filter',
        'style': {
            backgroundImage: 'url(\'./img/portada.jpg\')',
            backgroundSize: 'cover',
            backgroundPosition: 'top center'
        }
    }, React.createElement(Grid, {}, React.createElement(Row, {}, React.createElement(Col, {
        'md': 4,
        'mdOffset': 4,
        'sm': 6,
        'smOffset': 3
    }, React.createElement('div', { 'className': 'card card-signup' }, '\r\n                                    ', React.cloneElement(this.props.children, { 'authData': this.state.auth_data }), '\r\n                                ')))))))));
};