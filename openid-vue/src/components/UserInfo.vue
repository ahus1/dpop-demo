<script setup lang="ts">
import * as clientWithState from '../auth'
await clientWithState.refresh()
const res = await clientWithState.fetchUserInfo()
</script>

<template>
  User Info:
<pre>
{{ JSON.stringify(res, null, 2) }}
</pre>

<a @click="clientWithState.logout()">log out</a>

</template>
