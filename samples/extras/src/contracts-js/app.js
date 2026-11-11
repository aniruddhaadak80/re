// RevLens fixture source: a small web client that ships API contracts the way real bundles do.
import petstore from './petstore.json';
import { introspection, precompiled } from './generated.js';

const gql = (strings, ...values) => strings.reduce((a, s, i) => a + s + (i < values.length ? values[i] : ''), '');

const USER_FIELDS = gql`
  fragment UserFields on User {
    id
    email
    role
  }
`;

export const GET_USER = gql`
  query GetUser($id: ID!) {
    user(id: $id) {
      ...UserFields
      tags
    }
  }
  ${USER_FIELDS}
`;

export const CREATE_USER = gql`
  mutation CreateUser($input: CreateUserInput!) {
    createUser(input: $input) { id email }
  }
`;

export async function searchUsers(text) {
  const res = await fetch('/graphql', {
    method: 'POST',
    body: JSON.stringify({ query: 'query SearchUsers($text: String!) { search(text: $text) { __typename ... on User { id email } } }', variables: { text } }),
  });
  return res.json();
}

export function watch(id) {
  return { query: 'subscription UserEvents($id: ID!) { userEvents(id: $id) { id role } }', variables: { id } };
}

export const contracts = { petstore, introspection, precompiled };
console.log(Object.keys(contracts).length);
