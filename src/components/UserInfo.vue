<script setup lang="ts">
import * as clientWithState from '../auth'
const res = await clientWithState.fetchUserInfo()
</script>

<template>
  User Info:
  {{ res }}
</template>
