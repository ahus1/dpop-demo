<script setup lang="ts">
import * as clientWithState from '../auth'
const res = clientWithState.serverMetadata()
</script>

<template>
  Server Info:
  <pre>
{{ JSON.stringify(res, null, 2) }}
  </pre>
</template>
