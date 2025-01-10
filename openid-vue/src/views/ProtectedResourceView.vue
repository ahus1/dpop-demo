<script setup lang="ts">

import ProtectedResource from "@/components/ProtectedResource.vue";

</script>

<template>
  <main>
    <Suspense>
      <ProtectedResource />
      <template #fallback>
        Loading...
      </template>
    </Suspense>
  </main>
</template>
