import React from 'react/addons';
import _ from 'lodash';
import Navbar from 'react-bootstrap/lib/Navbar';
import Nav from 'react-bootstrap/lib/Nav';
import NavItem from 'react-bootstrap/lib/NavItem';
import NavDropdown from 'react-bootstrap/lib/NavDropdown';
import MenuItem from 'react-bootstrap/lib/MenuItem';
import DropdownButton from 'react-bootstrap/lib/DropdownButton';
import LinkContainer from 'react-router-bootstrap/lib/LinkContainer';
export default function () {
    return React.createElement(Navbar, { 'fixedTop': true }, React.createElement(Navbar.Header, {}, React.createElement(Navbar.Brand, {}, React.createElement('a', { 'href': '#' }, 'React-Bootstrap')), React.createElement(Navbar.Toggle, {})), React.createElement(Navbar.Collapse, {}, this.props.authData ? React.createElement(Nav, {}, React.createElement(LinkContainer, { 'to': { pathname: '/' } }, React.createElement(NavItem, {
        'eventKey': 1,
        'href': '#'
    }, this.i18n.t('navbar.home'))), React.createElement(LinkContainer, { 'to': { pathname: '/conversations' } }, React.createElement(NavItem, {
        'eventKey': 2,
        'href': '#'
    }, this.i18n.t('navbar.conversations')))) : null, !this.props.authData ? React.createElement(Nav, { 'pullRight': true }, React.createElement(LinkContainer, { 'to': { pathname: '/login' } }, React.createElement(NavItem, {
        'eventKey': 1,
        'href': '#'
    }, this.i18n.t('navbar.login'))), React.createElement(LinkContainer, { 'to': { pathname: '/signup' } }, React.createElement(NavItem, {
        'eventKey': 2,
        'href': '#'
    }, this.i18n.t('navbar.signup')))) : null, this.props.authData ? React.createElement(Nav, { 'pullRight': true }, React.createElement(DropdownButton, {
        'id': 'user-dropdown-button',
        'title': this.props.authData.password.email,
        'key': 1
    }, React.createElement(LinkContainer, { 'to': { pathname: '/logout' } }, React.createElement(MenuItem, { 'eventKey': 2 }, 'Logout')), React.createElement(LinkContainer, { 'to': { pathname: '/change-password' } }, React.createElement(MenuItem, { 'eventKey': 3 }, 'Change Password')))) : null));
};