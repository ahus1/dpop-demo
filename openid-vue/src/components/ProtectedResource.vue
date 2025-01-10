<script setup lang="ts">
import * as clientWithState from '../auth'

let headers = new Headers()
headers.set('accept', 'application/json')
headers.append('accept', 'application/jwt')
const res = await clientWithState.fetchProtectedResource(new URL('http://localhost:9090/hello')
    , 'GET', undefined, headers).then(value => value.text())

</script>

<template>
  Protected Resource:
  {{ res }}
</template>
