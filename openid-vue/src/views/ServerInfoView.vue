<script setup lang="ts">

import ServerInfo from "@/components/ServerInfo.vue";

</script>

<template>
  <main>
    <Suspense>
      <ServerInfo />
      <template #fallback>
        Loading...
      </template>
    </Suspense>
  </main>
</template>
