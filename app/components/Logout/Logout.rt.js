import React from 'react/addons';
import _ from 'lodash';
import Grid from 'react-bootstrap/lib/Grid';
import Row from 'react-bootstrap/lib/Row';
import Col from 'react-bootstrap/lib/Col';
import Alert from 'react-bootstrap/lib/Alert';
export default function () {
    return React.createElement('div', { 'className': 'signup-page' }, React.createElement('div', { 'className': 'wrapper' }, React.createElement('div', {
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
    }, React.createElement('div', { 'className': 'card card-signup' }, this.props.authData ? React.createElement(Alert, { 'bsStyle': 'info' }, React.createElement('div', { 'className': 'alert-icon' }, React.createElement('i', { 'className': 'material-icons' }, 'info_outline')), React.createElement('span', {}, 'Cerrando sesión, espere un momento')) : null, !this.props.authData ? React.createElement(Alert, { 'bsStyle': 'success' }, React.createElement('div', { 'className': 'alert-icon' }, React.createElement('i', { 'className': 'material-icons' }, 'info_outline')), React.createElement('span', {}, 'Sesión Cerrada con éxito')) : null)))))));
};